/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `z23-acme` — the node's certificate worker.
 *
 * WHY THIS IS A SEPARATE PROGRAM. Getting a certificate from Let's Encrypt
 * means being a TLS client with a CA trust store, and a program with a trust
 * store can be told who to trust by whoever ships that store. The node
 * refuses that property: test_cold_join_sovereign P2 asserts that no
 * Z23-authored object the node links carries an undefined reference to any
 * TLS-client or CA-trust-store entry point. So the CA conversation lives
 * out here, exactly as package verification lives in
 * `z23-package-verify`, and the node keeps doing the only thing it
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

#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACME_EXIT_OK      0
#define ACME_EXIT_FAILED  1
#define ACME_EXIT_USAGE   2
#define ACME_EXIT_DUE     3

static void usage(FILE *out)
{
    fputs(
        "z23-acme — issue and renew the node's TLS certificate\n"
        "\n"
        "  z23-acme obtain|renew --domain NAME --account PEM --cert PEM\n"
        "                               --key PEM --handoff PATH --agree-tos\n"
        "                               [--staging | --directory URL]\n"
        "                               [--email ADDRESS] [--timeout-ms N]\n"
        "                               [--poll-attempts N] [--poll-interval-ms N]\n"
        "  z23-acme check  --cert PEM\n"
        "  z23-acme selftest\n"
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
    const int64_t now = platform_time_wall_unix();
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

static int report_acme_selftest(void)
{
    const int failures = acme_selftest_transport() + acme_selftest_protocol();
    if (failures == 0) {
        printf("ALL SELFTESTS PASSED\n");
        return ACME_EXIT_OK;
    }
    printf("SOME SELFTESTS FAILED — %d check(s)\n", failures);
    return ACME_EXIT_FAILED;
}

/* Help and selftest exit before any option is read. Returns their exit
 * status, or -1 when `command` is neither. */
static int builtin_command_status(const char *command)
{
    if (strcmp(command, "--help") == 0 || strcmp(command, "help") == 0) {
        usage(stdout);
        return ACME_EXIT_OK;
    }
    if (strcmp(command, "selftest") == 0)
        return report_acme_selftest();
    return -1;
}

/* Returns ACME_EXIT_USAGE when `command` is not obtain, renew or check.
 * On success, *renew and *check record which of those it is. */
static int classify_command(const char *command, bool *renew, bool *check)
{
    const bool obtain = strcmp(command, "obtain") == 0;
    *renew = strcmp(command, "renew") == 0;
    *check = strcmp(command, "check") == 0;
    if (!obtain && !*renew && !*check) {
        fprintf(stderr, "z23-acme: unknown command \"%s\"\n", command);
        usage(stderr);
        return ACME_EXIT_USAGE;
    }
    return ACME_EXIT_OK;
}

/* How one argv flag was recognized. NONE means try the next group; BAD
 * means the flag matched but its value was missing or unusable. */
#define ACME_OPT_NONE 0
#define ACME_OPT_OK   1
#define ACME_OPT_BAD  2

static int match_string_option(int argc, char **argv, int *i, const char *a,
                               struct acme_client_config *cfg,
                               const char **cert_path)
{
    const char **dest = NULL;
    if (strcmp(a, "--domain") == 0)
        dest = &cfg->domain;
    else if (strcmp(a, "--account") == 0)
        dest = &cfg->account_key_path;
    else if (strcmp(a, "--cert") == 0)
        dest = cert_path;
    else if (strcmp(a, "--key") == 0)
        dest = &cfg->cert_key_path;
    else if (strcmp(a, "--handoff") == 0)
        dest = &cfg->handoff_path;
    else if (strcmp(a, "--email") == 0)
        dest = &cfg->contact_email;
    else if (strcmp(a, "--directory") == 0)
        dest = &cfg->directory_url;
    else
        return ACME_OPT_NONE;
    if (!take_value(argc, argv, i, dest))
        return ACME_OPT_BAD;
    return ACME_OPT_OK;
}

static int match_int_option(int argc, char **argv, int *i, const char *a,
                            struct acme_client_config *cfg)
{
    int *dest = NULL;
    if (strcmp(a, "--timeout-ms") == 0)
        dest = &cfg->timeout_ms;
    else if (strcmp(a, "--poll-attempts") == 0)
        dest = &cfg->poll_attempts;
    else if (strcmp(a, "--poll-interval-ms") == 0)
        dest = &cfg->poll_interval_ms;
    else
        return ACME_OPT_NONE;
    if (!take_int(argc, argv, i, dest))
        return ACME_OPT_BAD;
    return ACME_OPT_OK;
}

static int match_flag_option(const char *a, bool *staging,
                             struct acme_client_config *cfg)
{
    if (strcmp(a, "--staging") == 0) {
        *staging = true;
        return ACME_OPT_OK;
    }
    if (strcmp(a, "--agree-tos") == 0) {
        cfg->agree_terms_of_service = true;
        return ACME_OPT_OK;
    }
    return ACME_OPT_NONE;
}

static int parse_client_args(int argc, char **argv,
                             struct acme_client_config *cfg,
                             const char **cert_path, bool *staging)
{
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        int matched = match_string_option(argc, argv, &i, a, cfg, cert_path);
        if (matched == ACME_OPT_NONE)
            matched = match_int_option(argc, argv, &i, a, cfg);
        if (matched == ACME_OPT_NONE)
            matched = match_flag_option(a, staging, cfg);
        if (matched == ACME_OPT_NONE) {
            fprintf(stderr, "z23-acme: unknown option \"%s\"\n", a);
            usage(stderr);
            return ACME_EXIT_USAGE;
        }
        if (matched == ACME_OPT_BAD) {
            fprintf(stderr, "z23-acme: %s needs a value\n", a);
            return ACME_EXIT_USAGE;
        }
    }
    return ACME_EXIT_OK;
}

static int apply_staging_directory(bool staging, struct acme_client_config *cfg)
{
    if (staging && cfg->directory_url) {
        fprintf(stderr, "z23-acme: --staging and --directory both name a "
                        "certificate authority; pass one\n");
        return ACME_EXIT_USAGE;
    }
    if (staging)
        cfg->directory_url = ACME_DIRECTORY_LETSENCRYPT_STAGING;
    return ACME_EXIT_OK;
}

/* Print the renew verdict. Returns true when the certificate is still
 * current and the caller must not order. */
static bool renew_already_current(const char *cert_path)
{
    const int64_t now = platform_time_wall_unix();
    const enum acme_renewal_action action = acme_renewal_check(cert_path, now);
    if (action == ACME_RENEWAL_CURRENT) {
        printf("verdict=current cert=%s seconds_until_due=%lld — nothing to do\n",
               cert_path,
               (long long)acme_renewal_seconds_until_due(cert_path, now));
        return true;
    }
    printf("verdict=%s cert=%s — ordering\n",
           acme_renewal_action_name(action), cert_path);
    return false;
}

static int obtain_and_report(const struct acme_client_config *cfg)
{
    if (!acme_client_obtain(cfg))
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
    (void)acme_certificate_validity(cfg->cert_path, &not_before, &not_after);
    printf("issued cert=%s key=%s domain=%s not_after=%lld\n", cfg->cert_path,
           cfg->cert_key_path, cfg->domain, (long long)not_after);
    printf("the running node serves this on its next connection; no restart, "
           "and nothing else to run\n");
    return ACME_EXIT_OK;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return ACME_EXIT_USAGE;
    }
    const char *command = argv[1];

    const int builtin = builtin_command_status(command);
    if (builtin >= 0)
        return builtin;

    bool renew = false;
    bool check = false;
    const int known = classify_command(command, &renew, &check);
    if (known != ACME_EXIT_OK)
        return known;

    struct acme_client_config cfg = {0};
    const char *cert_path = NULL;
    bool staging = false;
    const int parsed = parse_client_args(argc, argv, &cfg, &cert_path, &staging);
    if (parsed != ACME_EXIT_OK)
        return parsed;
    cfg.cert_path = cert_path;

    if (!cert_path) {
        fprintf(stderr, "z23-acme: --cert names the certificate this "
                        "command reads or writes; it has no default\n");
        return ACME_EXIT_USAGE;
    }
    if (check)
        return report_check(cert_path);

    const int staged = apply_staging_directory(staging, &cfg);
    if (staged != ACME_EXIT_OK)
        return staged;

    if (renew && renew_already_current(cert_path))
        return ACME_EXIT_OK;

    return obtain_and_report(&cfg);
}
