/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: prove the install front door's release-pin judgement — the code
 * that decides whether a stranger's machine installs anything.
 *
 * This judgement used to live twice, in two languages, in two files served at
 * https://z23.sh and executed before anything had been verified. Neither copy
 * was reachable from this test runner, so neither was proved here: the sh
 * half was exercised by a shell harness and the PowerShell half by an
 * in-process selftest nobody on Linux ever ran. It is now one C23 library
 * (platform/modules/install), and every refusal it can make is asserted below, in BOTH
 * directions — the agreeing case resolves to a pin, and each way of breaking
 * agreement refuses.
 *
 * The three assertions that matter most, because getting any of them backwards
 * installs the wrong software or refuses to install the right software:
 *   1. the all-zero pin is a SENTINEL, never a pin;
 *   2. two answered sources that differ REFUSE — never a majority vote;
 *   3. a source that could not be reached is UNREACHABLE, never a dissenting
 *      opinion, so a captive portal cannot veto an install.
 *
 * tools/install/install_selftest.c drives the same decisions through the
 * real z23-bootstrap binary end to end, with real files, a real fork/exec and
 * a real handoff. This group proves the decisions themselves, including the
 * DNS wire cases an end-to-end harness cannot construct.
 */

#define _POSIX_C_SOURCE 200809L
#include "test/test_core.h"

#include "install/front_door.h"

#include <stdio.h>
#include <string.h>
#if !defined(_WIN32) && defined(ZCL_TESTING)
#include <stdarg.h>
#include "base/safe_alloc.h"
#include "../../../tools/acme/tls_client.h"
/* Real caller; local-only faults, fixed storage, no network or execution. */
static int fetch_fault;
static char fetch_storage[513], fetch_message[256];
static int fetch_diagnostic(FILE *f, const char *fmt, va_list ap)
{ (void)f; return vsnprintf(fetch_message, sizeof fetch_message, fmt, ap); }
static int fetch_error(FILE *f)
{ return fetch_fault == 1 ? (errno = EIO, 1) : ferror(f); }
static int fetch_close(FILE *f)
{ const int rc = fclose(f); return fetch_fault == 2 ? (errno = EIO, EOF) : rc; }
static int fetch_fixture_main(int argc, char **argv);
#define main fetch_fixture_main
#define ferror fetch_error
#define fclose fetch_close
#define vfprintf fetch_diagnostic
#define tls_client_fetch(req, resp) ((void)(req), memset((resp), 0, sizeof *(resp)), false)
#define tls_client_response_free(resp) ((void)(resp))
#undef zcl_malloc
#define zcl_malloc(size, label) ((size) <= sizeof fetch_storage ? fetch_storage : NULL)
#define free(ptr) ((void)(ptr))
#include "../../../tools/install/z23_bootstrap.c"
#undef main
#undef ferror
#undef fclose
#undef vfprintf
#undef tls_client_fetch
#undef tls_client_response_free
#undef zcl_malloc
#undef free
#endif
#define FD_CHECK(name, expr) do {                     \
    printf("z23_front_door: %s... ", (name));         \
    if (expr) { printf("OK\n"); }                     \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

static const char k_pin_a[] =
    "z23-pin-v1:"
    "1234567812345678123456781234567812345678123456781234567812345678:"
    "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01";
static const char k_pin_b[] =
    "z23-pin-v1:"
    "fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98:"
    "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01";

static bool parses(const char *text)
{
    struct fd_pin pin;
    return fd_pin_parse(text, &pin);
}

/* ── 1. The pin record ──────────────────────────────────────────────────── */
static int case_pin_parse(void)
{
    int failures = 0;
    struct fd_pin pin;
    const unsigned char zero[sizeof pin] = {0};
    static const char text[FD_PIN_MAX] =
        "z23-pin-v1:"
        "1234567812345678123456781234567812345678123456781234567812345678:"
        "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01";
    static const char manifest[] =
        "1234567812345678123456781234567812345678123456781234567812345678";
    static const char installer[] =
        "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01";

    FD_CHECK("a well-formed pin parses", fd_pin_parse(k_pin_a, &pin));
    FD_CHECK("the manifest half is carried out",
             memcmp(pin.manifest, manifest, sizeof pin.manifest) == 0);
    FD_CHECK("the installer half is carried out",
             memcmp(pin.installer, installer, sizeof pin.installer) == 0);
    FD_CHECK("the whole record is carried out verbatim",
             memcmp(pin.text, text, sizeof pin.text) == 0);

    /* The input may be the previous result's text: it must be read before
     * the output is reset. The header imposes no non-overlap restriction. */
    FD_CHECK("a pin reparses from its own output text",
             fd_pin_parse(pin.text, &pin));
    FD_CHECK("reparsing preserves every output field",
             memcmp(pin.text, text, sizeof pin.text) == 0 &&
             memcmp(pin.manifest, manifest, sizeof pin.manifest) == 0 &&
             memcmp(pin.installer, installer, sizeof pin.installer) == 0);

    /* THE SENTINEL. If this ever parses, "no release is pinned yet" becomes
     * "the all-zero release is pinned" and the front door installs it. */
    FD_CHECK("the all-zero sentinel is NOT a pin", !parses(FD_PIN_SENTINEL));
    FD_CHECK("the all-zero sentinel is recognised as the sentinel",
             fd_pin_is_sentinel(FD_PIN_SENTINEL));
    FD_CHECK("a real pin is not the sentinel", !fd_pin_is_sentinel(k_pin_a));
    FD_CHECK("out is zeroed when the sentinel is refused",
             !fd_pin_parse(FD_PIN_SENTINEL, &pin) &&
             memcmp(&pin, zero, sizeof pin) == 0);

    static const char *const refused[] = {
        FD_PIN_SENTINEL, NULL, "z23-pin-v1:short:short",
        "z23-pin-v2:"
        "1234567812345678123456781234567812345678123456781234567812345678:"
        "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01"
    };
    for (size_t i = 0; i < sizeof refused / sizeof refused[0]; i++) {
        FD_CHECK("a valid pin seeds the refusal fixture",
                 fd_pin_parse(k_pin_a, &pin));
        memset(&pin, 0xa5, sizeof pin);
        FD_CHECK("refusal clears every poisoned output byte",
                 !fd_pin_parse(refused[i], &pin) &&
                 memcmp(&pin, zero, sizeof pin) == 0);
    }

    FD_CHECK("a short pin does not parse", !parses("z23-pin-v1:short:short"));
    FD_CHECK("a foreign pin version does not parse",
             !parses("z23-pin-v2:"
                     "1234567812345678123456781234567812345678123456781234567812345678:"
                     "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01"));
    FD_CHECK("a third field does not parse",
             !parses("z23-pin-v1:"
                     "1234567812345678123456781234567812345678123456781234567812345678:"
                     "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01:x"));
    FD_CHECK("uppercase hex does not parse — one spelling, so two channels "
             "carrying the same pin compare equal",
             !parses("z23-pin-v1:"
                     "1234567812345678123456781234567812345678123456781234567812345678:"
                     "ABCDEF01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01"));
    FD_CHECK("a non-hex digit does not parse",
             !parses("z23-pin-v1:"
                     "g234567812345678123456781234567812345678123456781234567812345678:"
                     "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01"));
    FD_CHECK("a captive-portal answer does not parse",
             !parses("this-domain-is-parked"));
    FD_CHECK("an empty answer does not parse", !parses(""));
    FD_CHECK("a NULL answer does not parse", !parses(NULL));

    /* A TXT answer and a fetched file both arrive with whitespace on them. */
    char padded[FD_PIN_MAX + 8];
    (void)snprintf(padded, sizeof padded, "  %s \r\n", k_pin_a);
    FD_CHECK("surrounding whitespace is tolerated", parses(padded));
    return failures;
}

/* ── 2. Reading a pin out of a fetched file or a TXT answer ─────────────── */
static int case_pin_from_lines(void)
{
    int failures = 0;
    struct fd_pin pin;
    char blob[1024];

    (void)snprintf(blob, sizeof blob, "%s\n", k_pin_a);
    FD_CHECK("a RELEASE_PIN file yields its pin",
             fd_pin_from_lines(blob, &pin) && strcmp(pin.text, k_pin_a) == 0);

    /* The repository host serving an HTML 404 is the failure this guards:
     * it must read as "nothing is pinned here", not as a dissenting pin. */
    FD_CHECK("an HTML error page yields nothing",
             !fd_pin_from_lines("<html>404</html>\n", &pin));
    (void)snprintf(blob, sizeof blob, "%s\n", FD_PIN_SENTINEL);
    FD_CHECK("a file holding only the unset sentinel yields nothing",
             !fd_pin_from_lines(blob, &pin));
    (void)snprintf(blob, sizeof blob, "# a comment\n\n%s\n", k_pin_a);
    FD_CHECK("the first line that IS a pin wins",
             fd_pin_from_lines(blob, &pin) && strcmp(pin.text, k_pin_a) == 0);
    FD_CHECK("an empty blob yields nothing", !fd_pin_from_lines("", &pin));
    FD_CHECK("a NULL blob yields nothing", !fd_pin_from_lines(NULL, &pin));
    return failures;
}

/* ── 3. The consistency judgement ──────────────────────────────────────── */
static void answered(struct fd_attestation *a, const char *origin,
                     const char *text)
{
    struct fd_pin pin;
    (void)fd_pin_parse(text, &pin);
    fd_attestation_answered(a, origin, &pin);
}

static int case_attestation_oversized(void)
{
    int failures = 0;
    struct fd_attestation a;
    answered(&a, "abcdefghijklmnop", k_pin_a);
    FD_CHECK("oversized answered origin requests shortening to 15",
             !a.answered && a.origin[0] == '\0' && a.pin.text[0] == '\0' &&
             strcmp(a.reason, "shorten-origin-to-15") == 0);
    fd_attestation_unreachable(&a, "repo", "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr");
    FD_CHECK("oversized unreachable reason retains origin and requests 31",
             !a.answered && strcmp(a.origin, "repo") == 0 &&
             a.pin.text[0] == '\0' &&
             strcmp(a.reason, "shorten-reason-to-31") == 0);
    fd_attestation_unreachable(&a, "abcdefghijklmnop", "fetch-failed");
    FD_CHECK("oversized unreachable origin requests shortening to 15",
             !a.answered && a.origin[0] == '\0' && a.pin.text[0] == '\0' &&
             strcmp(a.reason, "shorten-origin-to-15") == 0);
    return failures;
}

static int case_attestation_controls(void)
{
    int failures = 0;
    struct fd_attestation a;
    const char *origin = "abcdefghijklmno";
    const char *reason = "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr";

    answered(&a, origin, k_pin_a);
    FD_CHECK("maximum answered origin remains exact",
             a.answered && strcmp(a.origin, origin) == 0 &&
             strcmp(a.pin.text, k_pin_a) == 0 && a.reason[0] == '\0');
    fd_attestation_unreachable(&a, origin, reason);
    FD_CHECK("maximum unreachable origin and reason remain exact",
             !a.answered && strcmp(a.origin, origin) == 0 &&
             strcmp(a.reason, reason) == 0);
    answered(&a, NULL, k_pin_a);
    FD_CHECK("NULL answered origin remains empty",
             a.answered && a.origin[0] == '\0');
    answered(&a, "", k_pin_a);
    FD_CHECK("empty answered origin remains empty",
             a.answered && a.origin[0] == '\0');
    fd_attestation_answered(&a, "repo", NULL);
    const struct fd_pin empty_pin = {0};
    FD_CHECK("NULL pin requests a pin and clears the previous pin",
             !a.answered && strcmp(a.origin, "repo") == 0 &&
             strcmp(a.reason, "supply-pin") == 0 &&
             memcmp(&a.pin, &empty_pin, sizeof a.pin) == 0);
    fd_attestation_unreachable(&a, NULL, NULL);
    FD_CHECK("NULL unreachable fields remain empty",
             !a.answered && a.origin[0] == '\0' && a.reason[0] == '\0');
    fd_attestation_unreachable(&a, "", "");
    FD_CHECK("empty unreachable fields remain empty",
             !a.answered && a.origin[0] == '\0' && a.reason[0] == '\0');
    return failures;
}

static int case_agreement(void)
{
    int failures = 0;
    struct fd_attestation att[3];
    struct fd_agreement got;

    answered(&att[0], "baked", k_pin_a);
    answered(&att[1], "dns", k_pin_a);
    answered(&att[2], "repo", k_pin_a);
    fd_agree(att, 3, &got);
    FD_CHECK("three agreeing sources agree",
             got.verdict == FD_VERDICT_AGREED &&
             strcmp(got.agreed.text, k_pin_a) == 0 && got.answered == 3 &&
             got.unreachable[0] == '\0');

    /* Losing DNS costs one vote. Demanding all three would hand a veto to any
     * resolver that drops TXT — that is the failure this asserts against. */
    fd_attestation_unreachable(&att[1], "dns", "no-resolver");
    fd_agree(att, 3, &got);
    FD_CHECK("two agreeing sources still agree",
             got.verdict == FD_VERDICT_AGREED && got.answered == 2 &&
             strcmp(got.agreed.text, k_pin_a) == 0);
    FD_CHECK("the missing source is named with its reason",
             strcmp(got.unreachable, "dns=no-resolver") == 0);

    /* NEVER a majority vote: 2-against-1 must refuse, because a rollback, a
     * half-finished publish and a compromise all look exactly like this. */
    answered(&att[1], "dns", k_pin_a);
    answered(&att[2], "repo", k_pin_b);
    fd_agree(att, 3, &got);
    FD_CHECK("one dissenting source refuses, it is never outvoted",
             got.verdict == FD_VERDICT_DISAGREE);
    FD_CHECK("the disagreement names both origins",
             strcmp(got.first_origin, "baked") == 0 &&
             strcmp(got.other_origin, "repo") == 0);
    FD_CHECK("the disagreement carries both pins",
             strcmp(got.first_pin, k_pin_a) == 0 &&
             strcmp(got.other_pin, k_pin_b) == 0);

    answered(&att[0], "baked", k_pin_a);
    answered(&att[1], "dns", k_pin_b);
    answered(&att[2], "repo", k_pin_a);
    fd_agree(att, 3, &got);
    FD_CHECK("a dissenting DNS record refuses even with baked+repo agreeing",
             got.verdict == FD_VERDICT_DISAGREE &&
             strcmp(got.other_origin, "dns") == 0);

    /* One source is not corroboration. No silent degradation to one channel. */
    answered(&att[0], "baked", k_pin_a);
    fd_attestation_unreachable(&att[1], "dns", "malformed-answer");
    fd_attestation_unreachable(&att[2], "repo", "fetch-failed");
    fd_agree(att, 3, &got);
    FD_CHECK("one answering source is refused by count",
             got.verdict == FD_VERDICT_NO_QUORUM && got.answered == 1);
    FD_CHECK("every missing source is named, in order, with its reason",
             strcmp(got.unreachable,
                    "dns=malformed-answer, repo=fetch-failed") == 0);

    fd_attestation_unreachable(&att[0], "baked", "no-release-pinned");
    fd_agree(att, 3, &got);
    FD_CHECK("no answering source is refused by count",
             got.verdict == FD_VERDICT_NO_QUORUM && got.answered == 0);
    FD_CHECK("an unpinned script says exactly that",
             strncmp(got.unreachable, "baked=no-release-pinned", 23) == 0);

    /* The sentinel path end to end: a script with nothing pinned into it is a
     * source that did not answer, and dns+repo carry the quorum without it. */
    struct fd_pin sentinel;
    FD_CHECK("the sentinel never becomes an attestation",
             !fd_pin_parse(FD_PIN_SENTINEL, &sentinel));
    fd_attestation_unreachable(&att[0], "baked", "no-release-pinned");
    answered(&att[1], "dns", k_pin_a);
    answered(&att[2], "repo", k_pin_a);
    fd_agree(att, 3, &got);
    FD_CHECK("dns+repo carry a quorum without a baked pin",
             got.verdict == FD_VERDICT_AGREED && got.answered == 2 &&
             strcmp(got.agreed.text, k_pin_a) == 0);
    return failures;
}

static void maximal_missing_sources(struct fd_attestation att[6])
{
    const char *origin = "ooooooooooooooo";
    const char *reason = "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr";

    answered(&att[0], "baked", k_pin_a);
    answered(&att[1], "dns", k_pin_a);
    for (size_t i = 2; i < 6; i++)
        fd_attestation_unreachable(&att[i], origin, reason);
}

static int case_unreachable_list_bounds(void)
{
    int failures = 0;
    const char *three =
        "ooooooooooooooo=rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr, "
        "ooooooooooooooo=rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr, "
        "ooooooooooooooo=rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr";
    struct fd_attestation att[6];
    struct fd_agreement got;

    maximal_missing_sources(att);

    fd_agree(att + 2, 3, &got);
    FD_CHECK("three maximal missing sources remain exact",
             got.verdict == FD_VERDICT_NO_QUORUM && got.total == 3 &&
             got.answered == 0 && strlen(got.unreachable) == 145 &&
             strcmp(got.unreachable, three) == 0);
    fd_agree(att, 5, &got);
    FD_CHECK("a complete maximal list preserves quorum",
             got.verdict == FD_VERDICT_AGREED && got.answered == 2 &&
             strcmp(got.agreed.text, k_pin_a) == 0 &&
             strcmp(got.unreachable, three) == 0);
    return failures;
}

static int case_unreachable_list_overflow(void)
{
    int failures = 0;
    struct fd_attestation att[6];
    struct fd_agreement got;

    maximal_missing_sources(att);
    fd_agree(att + 2, 4, &got);
    FD_CHECK("four maximal missing sources report list overflow",
             got.verdict == FD_VERDICT_NO_QUORUM && got.total == 4 &&
             got.answered == 0 && got.agreed.text[0] == '\0' &&
             strcmp(got.unreachable,
                    "missing-source list overflow at entry 4; "
                    "buffer 160 bytes; reduce the list") == 0);
    fd_agree(att, 6, &got);
    FD_CHECK("list overflow refuses even with two agreeing answers",
             got.verdict == FD_VERDICT_NO_QUORUM && got.total == 6 &&
             got.answered == 2 && got.agreed.text[0] == '\0' &&
             strcmp(got.unreachable,
                    "missing-source list overflow at entry 6; "
                    "buffer 160 bytes; reduce the list") == 0);
    return failures;
}

/* ── 4. The evidence handed to the second stage ────────────────────────── */
static int attest_arg_boundary(const struct fd_attestation *a, const char *want)
{
    int failures = 0;
    unsigned char guarded[FD_ATTEST_ARG_MAX + 2];
    const size_t n = strlen(want) + 1;
    char *out = (char *)&guarded[1];

    memset(guarded, 0xa5, sizeof guarded);
    FD_CHECK("exact argv capacity preserves the complete argument",
             fd_attest_arg(a, out, n) && memcmp(out, want, n) == 0);
    FD_CHECK("exact argv capacity preserves adjacent canaries",
             guarded[0] == 0xa5 && guarded[n + 1] == 0xa5);
    memset(guarded, 0xa5, sizeof guarded);
    FD_CHECK("one-byte-short argv capacity refuses and clears",
             !fd_attest_arg(a, out, n - 1) && out[0] == '\0');
    FD_CHECK("short argv capacity preserves adjacent canaries",
             guarded[0] == 0xa5 && guarded[n] == 0xa5);
    return failures;
}

static int case_attest_arg_guards(void)
{
    int failures = 0;
    struct fd_attestation a;
    unsigned char guarded[3] = {0xa5, 0xa5, 0xa5};
    const unsigned char want[3] = {0xa5, 0xa5, 0xa5};
    char *out = (char *)&guarded[1];

    fd_attestation_unreachable(&a, "repo", "fetch-failed");
    FD_CHECK("NULL attestation refuses without writing",
             !fd_attest_arg(NULL, out, 1) &&
             memcmp(guarded, want, sizeof guarded) == 0);
    FD_CHECK("NULL argv output refuses",
             !fd_attest_arg(&a, NULL, 1));
    FD_CHECK("zero argv capacity refuses without writing",
             !fd_attest_arg(&a, out, 0) &&
             memcmp(guarded, want, sizeof guarded) == 0);
    return failures;
}

static int case_attest_arg(void)
{
    int failures = 0;
    struct fd_attestation a;
    char arg[FD_ATTEST_ARG_MAX];
    char want[FD_ATTEST_ARG_MAX];

    answered(&a, "dns", k_pin_a);
    (void)snprintf(want, sizeof want, "--attest=dns=%s", k_pin_a);
    FD_CHECK("an answered source is passed through with its pin",
             fd_attest_arg(&a, arg, sizeof arg) && strcmp(arg, want) == 0);
    failures += attest_arg_boundary(&a, want);

    fd_attestation_unreachable(&a, "repo", "fetch-failed");
    FD_CHECK("an unreachable source is declared, with its reason",
             fd_attest_arg(&a, arg, sizeof arg) &&
             strcmp(arg, "--attest-unreachable=repo=fetch-failed") == 0);
    failures += attest_arg_boundary(&a, "--attest-unreachable=repo=fetch-failed");
    failures += case_attest_arg_guards();

    /* A silently truncated attestation would be a lie about the evidence. */
    char tiny[8];
    FD_CHECK("a buffer too small refuses rather than truncating",
             !fd_attest_arg(&a, tiny, sizeof tiny) && tiny[0] == '\0');
    return failures;
}

/* ── 5. The machine ────────────────────────────────────────────────────── */
static bool triple_is(const char *sysname, const char *machine,
                      const char *want)
{
    char got[FD_TRIPLE_MAX];
    fd_platform_triple(sysname, machine, got);
    return strcmp(got, want) == 0;
}

static int case_platform(void)
{
    int failures = 0;
    FD_CHECK("Linux/x86_64 is linux-x86_64",
             triple_is("Linux", "x86_64", "linux-x86_64"));
    FD_CHECK("Linux/amd64 is the same triple",
             triple_is("Linux", "amd64", "linux-x86_64"));
    /* The Mac names itself what build_release.sh names the Mac artifact.
     * These two lines used to assert the opposite, and that assertion was
     * the bug: it froze a triple no publisher produces. */
    FD_CHECK("Darwin/arm64 is darwin-arm64",
             triple_is("Darwin", "arm64", "darwin-arm64"));
    FD_CHECK("a Linux arm box keeps its own spelling, not the Mac's",
             triple_is("Linux", "aarch64", "linux-aarch64"));
    /* An unrecognised machine is named, not guessed at: a wrong guess sends
     * the user to a 404 instead of telling them the truth. */
    FD_CHECK("an unknown kernel passes through verbatim",
             triple_is("SunOS", "sparc64", "SunOS-sparc64"));
    FD_CHECK("an empty uname is still a name we can print",
             triple_is("", "", "unknown-unknown"));

    FD_CHECK("linux-x86_64 is published",
             fd_platform_published("linux-x86_64"));
    FD_CHECK("darwin-arm64 is NOT published — no runtime is built for it",
             !fd_platform_published("darwin-arm64"));
    FD_CHECK("windows-x86_64 is NOT published",
             !fd_platform_published("windows-x86_64"));
    FD_CHECK("a prefix of a published triple is not published",
             !fd_platform_published("linux"));
    FD_CHECK("the empty triple is not published", !fd_platform_published(""));
    FD_CHECK("NULL is not published", !fd_platform_published(NULL));
    /* The refusal must name what we DO publish, and that text must be the
     * same list the membership test uses. */
    FD_CHECK("the published list names linux-x86_64",
             strcmp(fd_platform_published_list(), "linux-x86_64") == 0);
    return failures;
}

/* ── 6. The DNS TXT wire ───────────────────────────────────────────────── */
static size_t put_header(unsigned char *m, uint16_t id, uint16_t flags,
                         uint16_t qd, uint16_t an)
{
    m[0] = (unsigned char)(id >> 8);      m[1] = (unsigned char)id;
    m[2] = (unsigned char)(flags >> 8);   m[3] = (unsigned char)flags;
    m[4] = (unsigned char)(qd >> 8);      m[5] = (unsigned char)qd;
    m[6] = (unsigned char)(an >> 8);      m[7] = (unsigned char)an;
    m[8] = 0; m[9] = 0; m[10] = 0; m[11] = 0;
    return 12;
}

/* "_z23-pin.example" as two wire labels, then QTYPE/QCLASS. */
static size_t put_question(unsigned char *m, size_t at)
{
    static const unsigned char q[] = {
        8, '_','z','2','3','-','p','i','n',
        7, 'e','x','a','m','p','l','e',
        0, 0, 16, 0, 1
    };
    memcpy(m + at, q, sizeof q);
    return at + sizeof q;
}

/* A TXT answer whose owner name is the compression pointer 0xC00C back to the
 * question — the shape every real resolver emits. */
static size_t put_txt_answer(unsigned char *m, size_t at, const char *text)
{
    const size_t n = strlen(text);
    m[at++] = 0xc0; m[at++] = 0x0c;
    m[at++] = 0; m[at++] = 16;   /* TYPE = TXT */
    m[at++] = 0; m[at++] = 1;    /* CLASS = IN */
    m[at++] = 0; m[at++] = 0; m[at++] = 0; m[at++] = 60;  /* TTL */
    const size_t rdlength = n + 1;
    m[at++] = (unsigned char)(rdlength >> 8);
    m[at++] = (unsigned char)rdlength;
    m[at++] = (unsigned char)n;
    memcpy(m + at, text, n);
    return at + n;
}

static int case_dns_query(void)
{
    int failures = 0;
    unsigned char q[FD_DNS_QUERY_MAX];

    const size_t n = fd_dns_txt_query(0x1234, "_z23-pin.example", q, sizeof q);
    FD_CHECK("a TXT question is built", n == 12 + 18 + 4);
    FD_CHECK("the query carries our transaction id",
             n > 2 && q[0] == 0x12 && q[1] == 0x34);
    FD_CHECK("recursion is requested — we are asking a caching resolver",
             n > 3 && q[2] == 0x01 && q[3] == 0x00);
    FD_CHECK("exactly one question is asked",
             n > 5 && q[4] == 0 && q[5] == 1);
    FD_CHECK("the name is length-prefixed labels",
             n > 21 && q[12] == 8 && memcmp(q + 13, "_z23-pin", 8) == 0 &&
             q[21] == 7);
    FD_CHECK("the question ends TXT/IN",
             n >= 4 && q[n - 4] == 0 && q[n - 3] == 16 && q[n - 2] == 0 &&
             q[n - 1] == 1);
    FD_CHECK("a trailing dot is the root label, not an empty one",
             fd_dns_txt_query(1, "_z23-pin.example.", q, sizeof q) == n);
    FD_CHECK("an empty label is refused",
             fd_dns_txt_query(1, "_z23-pin..example", q, sizeof q) == 0);
    FD_CHECK("an empty name is refused",
             fd_dns_txt_query(1, "", q, sizeof q) == 0);
    char toolong[300];
    memset(toolong, 'a', sizeof toolong - 1);
    toolong[sizeof toolong - 1] = '\0';
    FD_CHECK("a name over 253 characters is refused",
             fd_dns_txt_query(1, toolong, q, sizeof q) == 0);
    char label64[80];
    memset(label64, 'a', 64);
    label64[64] = '\0';
    FD_CHECK("a label over 63 characters is refused",
             fd_dns_txt_query(1, label64, q, sizeof q) == 0);
    FD_CHECK("a buffer too small is refused",
             fd_dns_txt_query(1, "_z23-pin.example", q, 8) == 0);
    return failures;
}

static int case_dns_parse(void)
{
    int failures = 0;
    unsigned char m[512];
    struct fd_dns_txt txt;

    size_t at = put_header(m, 0x1234, 0x8180, 1, 1);
    at = put_question(m, at);
    at = put_txt_answer(m, at, k_pin_a);
    FD_CHECK("a normal TXT answer parses",
             fd_dns_txt_parse(m, at, 0x1234, &txt) == FD_DNS_OK &&
             txt.count == 1 && strcmp(txt.s[0], k_pin_a) == 0);

    /* An answer to a question we did not ask is not our answer. This is the
     * only cheap off-path check plain DNS gives us; without it anything that
     * can guess the source port writes our second consistency channel. */
    FD_CHECK("a reply carrying someone else's id is malformed",
             fd_dns_txt_parse(m, at, 0x1235, &txt) == FD_DNS_MALFORMED);

    unsigned char q[512];
    memcpy(q, m, at);
    q[2] = 0x01; q[3] = 0x00;   /* QR cleared: this is a question, not a reply */
    FD_CHECK("a query echoed back at us is malformed",
             fd_dns_txt_parse(q, at, 0x1234, &txt) == FD_DNS_MALFORMED);

    memcpy(q, m, at);
    q[2] = 0x83;                /* TC set */
    FD_CHECK("a truncated answer is reported as truncated, not as a pin",
             fd_dns_txt_parse(q, at, 0x1234, &txt) == FD_DNS_TRUNCATED);

    memcpy(q, m, at);
    q[3] = 0x83;                /* RCODE = NXDOMAIN */
    FD_CHECK("NXDOMAIN is no answer",
             fd_dns_txt_parse(q, at, 0x1234, &txt) == FD_DNS_NO_ANSWER);

    size_t empty = put_header(m, 7, 0x8180, 1, 0);
    empty = put_question(m, empty);
    FD_CHECK("an answer section with no records is no answer",
             fd_dns_txt_parse(m, empty, 7, &txt) == FD_DNS_NO_ANSWER);

    FD_CHECK("a runt datagram is malformed",
             fd_dns_txt_parse(m, 4, 7, &txt) == FD_DNS_MALFORMED);

    /* A compression pointer that points FORWARD or at itself is how a naive
     * parser is made to spin forever on one hostile datagram. */
    at = put_header(m, 9, 0x8180, 1, 1);
    at = put_question(m, at);
    m[at] = 0xc0; m[at + 1] = (unsigned char)at;  /* points at itself */
    m[at + 2] = 0; m[at + 3] = 16; m[at + 4] = 0; m[at + 5] = 1;
    m[at + 6] = 0; m[at + 7] = 0; m[at + 8] = 0; m[at + 9] = 0;
    m[at + 10] = 0; m[at + 11] = 0;
    FD_CHECK("a self-referential compression pointer is malformed",
             fd_dns_txt_parse(m, at + 12, 9, &txt) == FD_DNS_MALFORMED);

    /* RDLENGTH claiming more bytes than the datagram holds. */
    at = put_header(m, 11, 0x8180, 1, 1);
    at = put_question(m, at);
    const size_t rr = at;
    at = put_txt_answer(m, at, k_pin_a);
    m[rr + 10] = 0xff; m[rr + 11] = 0xff;
    FD_CHECK("rdlength past the end of the datagram is malformed",
             fd_dns_txt_parse(m, at, 11, &txt) == FD_DNS_MALFORMED);

    /* A character-string length that runs past its own RDATA. */
    at = put_header(m, 13, 0x8180, 1, 1);
    at = put_question(m, at);
    const size_t rr2 = at;
    at = put_txt_answer(m, at, k_pin_a);
    m[rr2 + 12] = 0xff;
    FD_CHECK("a character-string running past its rdata is malformed",
             fd_dns_txt_parse(m, at, 13, &txt) == FD_DNS_MALFORMED);

    /* Two answers, the pin second: a TXT name commonly carries other records
     * (SPF, verification tokens) and the front door must still find the pin. */
    at = put_header(m, 15, 0x8180, 1, 2);
    at = put_question(m, at);
    at = put_txt_answer(m, at, "v=spf1 -all");
    at = put_txt_answer(m, at, k_pin_a);
    FD_CHECK("every TXT string in the answer is collected",
             fd_dns_txt_parse(m, at, 15, &txt) == FD_DNS_OK && txt.count == 2 &&
             strcmp(txt.s[1], k_pin_a) == 0);
    struct fd_pin found;
    bool picked = false;
    for (size_t i = 0; i < txt.count && !picked; i++)
        picked = fd_pin_parse(txt.s[i], &found);
    FD_CHECK("the pin is picked out of the unrelated records",
             picked && strcmp(found.text, k_pin_a) == 0);

    /* A record type we did not ask about is skipped, not refused: a TXT name
     * behind a CNAME is a legitimate answer. */
    at = put_header(m, 17, 0x8180, 1, 2);
    at = put_question(m, at);
    const size_t cname = at;
    at = put_txt_answer(m, at, k_pin_a);
    m[cname + 3] = 5;   /* TYPE = CNAME */
    at = put_txt_answer(m, at, k_pin_a);
    FD_CHECK("a non-TXT record in the answer section is skipped",
             fd_dns_txt_parse(m, at, 17, &txt) == FD_DNS_OK && txt.count == 1);

    /* The portal case, all the way through: a resolver that answers with
     * something that is not a pin is UNREACHABLE, never a dissenting vote. */
    at = put_header(m, 19, 0x8180, 1, 1);
    at = put_question(m, at);
    at = put_txt_answer(m, at, "this-domain-is-parked");
    struct fd_pin portal;
    FD_CHECK("a captive-portal TXT answer parses on the wire but is no pin",
             fd_dns_txt_parse(m, at, 19, &txt) == FD_DNS_OK &&
             !fd_pin_parse(txt.s[0], &portal));
    return failures;
}

/* ── 8. The stamped shim an install origin serves ───────────────────────────
 *
 * A node stamped as an install origin owns GET / and GET /install.sh. While
 * platform/packaging/install/install.sh still carries the all-zero sentinel,
 * every one of those two answers is a script that refuses before it opens a
 * socket, and it hides the node's own source-build installer behind it. So
 * the boot wiring asks these bytes whether they name anything installable
 * before it arms that tree (boot_https_arm_public_install in
 * engine/composition/src/boot_frontend_services.c). */
static int case_shim_pin(void)
{
    static const char sentinel_shim[] =
        "#!/bin/sh\n"
        "PUBLISHED_PLATFORMS=\" linux-x86_64 \"\n"
        "BOOT_ZERO="
        "0000000000000000000000000000000000000000000000000000000000000000\n"
        "BOOT_LINUX_X86_64=\"$BOOT_ZERO\"\n"
        "curl --max-filesize 33554432 -fsSL \"$ORIGIN/bootstrap/$PLATFORM\"\n"
        "[ \"$WANT\" != \"$BOOT_ZERO\" ] || die \"no Z23 bootstrap is pinned"
        " into this script yet\"\n";
    static const char released_shim[] =
        "#!/bin/sh\n"
        "BOOT_ZERO="
        "0000000000000000000000000000000000000000000000000000000000000000\n"
        "BOOT_LINUX_X86_64=\""
        "9f2c4e6a8b0d1f3574695a8c7e2d4b6f8091a3c5e7d9fb02143658a7c9e0d2f4"
        "\"\n";
    int failures = 0;

    FD_CHECK("the checked-in sentinel shim names no bootstrap",
             !fd_shim_names_a_bootstrap(sentinel_shim));
    FD_CHECK("a release-cut shim names one",
             fd_shim_names_a_bootstrap(released_shim));
    FD_CHECK("the sentinel digest alone is not a name",
             !fd_shim_names_a_bootstrap(
                 "0000000000000000000000000000000000000000"
                 "000000000000000000000000"));
    FD_CHECK("a shim carrying no digest at all names nothing",
             !fd_shim_names_a_bootstrap("#!/bin/sh\necho z23-install\n"));
    FD_CHECK("a 63-character hex run is not a digest",
             !fd_shim_names_a_bootstrap(
                 "BOOT=9f2c4e6a8b0d1f3574695a8c7e2d4b6f"
                 "8091a3c5e7d9fb02143658a7c9e0d2f\n"));
    FD_CHECK("a 65-character hex run is not a digest either",
             !fd_shim_names_a_bootstrap(
                 "BOOT=9f2c4e6a8b0d1f3574695a8c7e2d4b6f"
                 "8091a3c5e7d9fb02143658a7c9e0d2f4a\n"));
    FD_CHECK("uppercase hex is not a digest — one spelling, as with a pin",
             !fd_shim_names_a_bootstrap(
                 "BOOT=\"9F2C4E6A8B0D1F3574695A8C7E2D4B6F"
                 "8091A3C5E7D9FB02143658A7C9E0D2F4\"\n"));
    FD_CHECK("empty text names nothing", !fd_shim_names_a_bootstrap(""));
    FD_CHECK("NULL text names nothing", !fd_shim_names_a_bootstrap(NULL));
    return failures;
}

#if !defined(_WIN32) && defined(ZCL_TESTING)
static int seed_fault, seed_fd;
static bool seed_capture;
static char seed_message[1024];
static void seed_report(const char *operation, const char *path, int error,
                        const char *repair)
{
    (void)snprintf(seed_message, sizeof seed_message,
                   "front door fetch fixture: %s failed: %s: %s; %s\n",
                   operation, path, strerror(error), repair);
    if (!seed_capture) (void)fputs(seed_message, stderr);
}
static size_t seed_write(const void *bytes, size_t len, FILE *f)
{
    if (seed_fault == 3) { errno = ENOSPC; return 2; }
    return fwrite(bytes, 1, len, f);
}
static int seed_close(FILE *f)
{
    const int rc = fclose(f);
    return seed_fault == 4 ? (errno = EIO, EOF) : rc;
}
static bool fetch_seed(const void *bytes, size_t len, char path[PATH_MAX])
{
    path[0] = '\0';
    seed_message[0] = '\0';
    const int fd = seed_fault == 1 ? (errno = ENOSPC, -1)
                                 : test_mkstemp(path, PATH_MAX, "front_door_fetch");
    seed_fd = fd;
    if (fd < 0) {
        seed_report("create", "front_door_fetch temporary-file template", errno,
                    "free fixture storage; check writable temporary directory");
        return false;
    }
    FILE *f = seed_fault == 2 ? (errno = EMFILE, NULL) : fdopen(fd, "wb");
    if (!f) {
        seed_report("fdopen", path, errno, "close excess descriptors");
        (void)close(fd);
        (void)unlink(path);
        return false;
    }
    errno = 0;
    const bool written = seed_write(bytes, len, f) == len;
    const int write_error = errno;
    const int closed = seed_close(f);
    const int close_error = errno;
    if (!written || closed != 0) {
        if (!written) seed_report("short write", path, write_error ? write_error : EIO,
                                  "free fixture storage; check writable temporary directory");
        else seed_report("close", path, close_error, "check writable temporary directory");
        (void)unlink(path);
        return false;
    }
    return true;
}

static int case_seed_failure(int fault)
{
    int failures = 0;
    const char *operations[] = {"", "create failed:", "fdopen failed:", "short write failed:", "close failed:"};
    const char *repairs[] = {"", "free fixture storage", "close excess descriptors",
                            "free fixture storage", "check writable temporary directory"};
    const int errors[] = {0, ENOSPC, EMFILE, ENOSPC, EIO};
    char path[PATH_MAX];
    seed_fault = fault;
    seed_capture = true;
    const bool seeded = fetch_seed("pin", 3, path);
    seed_fault = 0;
    seed_capture = false;
    FD_CHECK(operations[fault], !seeded && strstr(seed_message, operations[fault]) &&
             strstr(seed_message, fault == 1 ? "front_door_fetch temporary-file template" : path) &&
             strstr(seed_message, strerror(errors[fault])) && strstr(seed_message, repairs[fault]));
    if (fault != 1) {
        FD_CHECK("failed seed removes its fixture", path[0] && access(path, F_OK) == -1 && errno == ENOENT);
        FD_CHECK("failed seed closes its descriptor", fcntl(seed_fd, F_GETFD) == -1 && errno == EBADF);
        if (seeded) (void)unlink(path);
    } else FD_CHECK("create fault opens no fixture", path[0] == '\0' && seed_fd == -1);
    return failures;
}

static int case_seed_success(void)
{
    int failures = 0;
    char path[PATH_MAX], bytes[4] = {0};
    const bool seeded = fetch_seed("pin", 3, path);
    FD_CHECK("successful seed has no diagnostic", seeded && seed_message[0] == '\0');
    if (!seeded) return failures;
    FD_CHECK("successful seed closes its descriptor", fcntl(seed_fd, F_GETFD) == -1 && errno == EBADF);
    FILE *f = fopen(path, "rb");
    FD_CHECK("successful seed contains exactly three bytes", f && fread(bytes, 1, sizeof bytes, f) == 3 &&
             memcmp(bytes, "pin", 3) == 0 && !ferror(f));
    if (f) FD_CHECK("successful seed read closes", fclose(f) == 0);
    FD_CHECK("successful seed fixture removed", unlink(path) == 0);
    return failures;
}

static int case_fetch_error(int fault, const char *url)
{
    int failures = 0;
    char *body = (char *)"unchanged";
    size_t len = 99;
    fetch_fault = fault;
    fetch_message[0] = '\0';
    const bool ok = fetch_bounded(url, 64, 0, &body, &len);
    FD_CHECK(fault == 1 ? "prefix plus read EIO refuses" : "close EIO refuses",
             !ok && body == NULL && len == 0 && errno == EIO &&
             strstr(fetch_message, fault == 2 ? "close" : "read") &&
             !memcmp(fetch_storage, "pin", 3));
    return failures;
}

static int case_repo_bytes(bool embedded_nul)
{
    int failures = 0;
    char bytes[sizeof k_pin_a + 6];
    memcpy(bytes, k_pin_a, sizeof k_pin_a);
    memcpy(bytes + sizeof k_pin_a, "broken", 6);
    const size_t len = embedded_nul ? sizeof bytes : sizeof k_pin_a - 1;
    char path[PATH_MAX], url[PATH_MAX + 8];
    const bool seeded = fetch_seed(bytes, len, path);
    FD_CHECK("repository byte fixture created", seeded);
    if (!seeded) return failures;
    (void)snprintf(url, sizeof url, "file://%s", path);
    struct fd_attestation att;
    memset(&att, 0xa5, sizeof att);
    repo_attestation(url, &att);
    if (embedded_nul) {
        FD_CHECK("repository valid pin/NUL/suffix refuses the complete body",
                 !att.answered && strcmp(att.origin, "repo") == 0 &&
                 strcmp(att.reason, "malformed-answer") == 0 && att.pin.text[0] == '\0');
    } else {
        FD_CHECK("repository final pin without newline is answered",
                 att.answered && strcmp(att.origin, "repo") == 0 &&
                 strcmp(att.pin.text, k_pin_a) == 0 && att.reason[0] == '\0');
    }
    FD_CHECK("repository byte fixture removed", unlink(path) == 0);
    return failures;
}
#endif

static int case_fetch_errors(void)
{
    int failures = 0;
#if !defined(_WIN32) && defined(ZCL_TESTING)
    (void)fetch_fixture_main;
    for (int fault = 1; fault <= 4; ++fault) failures += case_seed_failure(fault);
    failures += case_seed_success();
    char path[PATH_MAX], url[PATH_MAX + 8];
    const bool seeded = fetch_seed("pin", 3, path);
    FD_CHECK("local read/close fixture created", seeded);
    if (!seeded) return failures;
    (void)snprintf(url, sizeof url, "file://%s", path);
    g_test_urls = true;
    failures += case_fetch_error(1, url);
    failures += case_fetch_error(2, url);
    fetch_fault = 0;
    failures += case_repo_bytes(true);
    failures += case_repo_bytes(false);
    g_test_urls = false;
    FD_CHECK("local read/close fixture removed", unlink(path) == 0);
#endif
    return failures;
}
int test_z23_front_door(void)
{
    int failures = 0;
    failures += case_pin_parse();
    failures += case_pin_from_lines();
    failures += case_attestation_oversized();
    failures += case_attestation_controls();
    failures += case_agreement();
    failures += case_unreachable_list_bounds();
    failures += case_unreachable_list_overflow();
    failures += case_attest_arg();
    failures += case_platform();
    failures += case_dns_query();
    failures += case_dns_parse();
    failures += case_shim_pin();
    failures += case_fetch_errors();
    printf("z23_front_door: %d failure(s)\n", failures);
    return failures;
}
