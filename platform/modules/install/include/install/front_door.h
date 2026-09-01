/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * front_door — the release-pin judgement the install front door makes, as
 * pure C23 with no I/O in it at all.
 *
 * WHY THIS IS A LIBRARY AND NOT A SHELL SCRIPT ANY MORE.
 * platform/packaging/install/install.sh is served at the project domain and piped
 * straight into a shell, so every line of it executes BEFORE anything has
 * been verified: a compromised origin replaces the checks along with the
 * program. Logic that lives in that shim is logic an attacker gets for free.
 * The shim was 206 lines of POSIX sh with a 322-line PowerShell twin that had
 * to be kept in step by hand; both are now ~30 lines that fetch and
 * digest-verify ONE bootstrap binary, and everything they used to decide is
 * decided here — once, in one language, for all three platforms.
 *
 * Nothing in this header touches a socket, a file, the clock, or the
 * environment. That is deliberate: the decisions below are exactly the ones
 * that say whether a stranger's machine installs anything, and a decision you
 * can only observe by running a network is a decision nobody tests. The
 * transports live in tools/install/z23_bootstrap.c.
 *
 * The judgement itself is UNCHANGED from the shell it replaces:
 *   - the all-zero pin is the "no release is pinned yet" SENTINEL, it is not
 *     a pin, and it never counts as a source that answered;
 *   - two answered pins that differ REFUSE — never a majority vote, because
 *     disagreement means a rollback, a half-finished publish or a compromise,
 *     and installing the winner would hide it;
 *   - fewer than two answered REFUSE — one source is not corroboration;
 *   - a source that could not be reached is UNREACHABLE, is named with its
 *     reason, and is never rendered as disagreement. Demanding all three
 *     would hand a veto to any resolver that drops TXT.
 */

#ifndef ZCL_INSTALL_FRONT_DOOR_H
#define ZCL_INSTALL_FRONT_DOOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* "z23-pin-v1:" + 64 hex + ":" + 64 hex + NUL = 141. Rounded up so a caller
 * can hold a slightly over-long candidate long enough to reject it. */
#define FD_PIN_MAX 160
#define FD_HEX_LEN 64
#define FD_ORIGIN_MAX 16
#define FD_REASON_MAX 32
/* "baked=no-release-pinned, dns=malformed-answer, repo=fetch-failed" + NUL. */
#define FD_UNREACHABLE_MAX 160
#define FD_TRIPLE_MAX 64
/* "--attest-unreachable=" + origin + "=" + pin-or-reason + NUL. */
#define FD_ATTEST_ARG_MAX (FD_PIN_MAX + FD_ORIGIN_MAX + 40)

extern const char FD_PIN_SENTINEL[];

struct fd_pin {
    char text[FD_PIN_MAX];
    char manifest[FD_HEX_LEN + 1];
    char installer[FD_HEX_LEN + 1];
};

/* z23-pin-v1:<64 hex manifest>:<64 hex installer> — no spaces, so a pin is
 * one argv element and one DNS TXT character-string, needing no quoting
 * anywhere.
 *
 * Returns false for anything that is not exactly that, INCLUDING the all-zero
 * sentinel: callers turn a false here into UNREACHABLE, never into a
 * dissenting opinion, which is what stops a captive portal's "this-domain-is-
 * parked" from tripping the loudest refusal we have. Surrounding ASCII
 * whitespace is tolerated because a TXT answer and a repository file both
 * arrive with it. `out` is zeroed on failure. */
bool fd_pin_parse(const char *text, struct fd_pin *out);

/* True for the all-zero record and nothing else. Kept separate from
 * fd_pin_parse so the caller can report "no release is pinned yet" rather
 * than the misleading "malformed". */
bool fd_pin_is_sentinel(const char *text);

/* Scan a NUL-terminated blob line by line and yield the first line that is a
 * pin. This is how the repository channel (a fetched RELEASE_PIN file) and a
 * multi-string TXT answer are read: an HTML error page or an unset sentinel
 * yields false, which the caller reports as malformed-answer. */
bool fd_pin_from_lines(const char *blob, struct fd_pin *out);

struct fd_attestation {
    char origin[FD_ORIGIN_MAX];   /* "baked" | "dns" | "repo" */
    bool answered;
    struct fd_pin pin;            /* meaningful only when answered */
    char reason[FD_REASON_MAX];   /* meaningful only when !answered */
};

void fd_attestation_answered(struct fd_attestation *a, const char *origin,
                             const struct fd_pin *pin);
void fd_attestation_unreachable(struct fd_attestation *a, const char *origin,
                                const char *reason);

enum fd_verdict {
    FD_VERDICT_AGREED = 0,
    FD_VERDICT_DISAGREE,
    FD_VERDICT_NO_QUORUM,
};

struct fd_agreement {
    enum fd_verdict verdict;
    struct fd_pin agreed;              /* set only when AGREED */
    size_t answered;
    size_t total;
    char unreachable[FD_UNREACHABLE_MAX];  /* "" when every source answered */
    /* On DISAGREE: the first answering source and the one that contradicted
     * it, so the refusal can print both pins and name both origins. The order
     * is the order the attestations were passed in, which is the order the
     * shell considered them (baked, dns, repo). */
    char first_origin[FD_ORIGIN_MAX];
    char first_pin[FD_PIN_MAX];
    char other_origin[FD_ORIGIN_MAX];
    char other_pin[FD_PIN_MAX];
};

/* The whole consistency judgement, in the order given. */
void fd_agree(const struct fd_attestation *att, size_t count,
              struct fd_agreement *out);

/* Render one attestation as the argv element handed to the second-stage
 * installer, so it judges the same evidence itself:
 *   --attest=<origin>=<pin>   |   --attest-unreachable=<origin>=<reason>
 * Returns false only if `out` is too small, which FD_ATTEST_ARG_MAX prevents. */
bool fd_attest_arg(const struct fd_attestation *a, char *out, size_t out_len);

/* ── The machine ──────────────────────────────────────────────────────────
 * uname(2) spellings vary by kernel and by 32/64-bit personality; the triple
 * in a URL and in a refusal must not. Anything we do not recognise is passed
 * through verbatim rather than guessed at, so the refusal names the machine
 * the user actually has. */
void fd_platform_triple(const char *sysname, const char *machine,
                        char out[FD_TRIPLE_MAX]);

/* linux-x86_64 is the whole published set today. That is narrower than what
 * platform/packaging/release/build_release.sh can package — a Windows runtime is built
 * and not published; see front_door_platform.c for why — because refusing a
 * machine we do not publish for, by name, beats installing a binary nobody
 * has ever run on it. */
bool fd_platform_published(const char *triple);
const char *fd_platform_published_list(void);

/* ── DNS TXT, on the wire ─────────────────────────────────────────────────
 * The shell shelled out to dig, host or nslookup and reported no-dns-tool
 * when a genuinely minimal container had none of them. A stranger should not
 * need a DNS utility installed to check a release pin, so the query is built
 * and parsed here and the transport is 40 lines of UDP in the bootstrap. The
 * DECISIONS are unchanged; only the reason strings for an unreachable DNS
 * channel differ, because "no dig on PATH" is no longer a thing that can
 * happen. */
#define FD_DNS_MAX_STRINGS 8
#define FD_DNS_STRING_MAX 256
#define FD_DNS_QUERY_MAX 512

struct fd_dns_txt {
    char s[FD_DNS_MAX_STRINGS][FD_DNS_STRING_MAX];
    size_t count;
};

/* Build a single recursive TXT question. Returns the length written, or 0 if
 * the name is unusable (empty label, label over 63, name over 253) or `out`
 * is too small. */
size_t fd_dns_txt_query(uint16_t id, const char *name,
                        unsigned char *out, size_t out_len);

enum fd_dns_status {
    FD_DNS_OK = 0,
    FD_DNS_NO_ANSWER,   /* well-formed, but nothing we asked for came back */
    FD_DNS_TRUNCATED,   /* TC set: the answer did not fit a datagram */
    FD_DNS_MALFORMED,   /* not a reply to our question, or unparsable */
};

/* Parse a response to the query `id` and collect its TXT character-strings.
 * Compression pointers are followed only BACKWARDS and only a bounded number
 * of times: a message that points forward or in a loop is malformed, and a
 * parser that trusted it would spin forever on a hostile datagram. */
enum fd_dns_status fd_dns_txt_parse(const unsigned char *msg, size_t len,
                                    uint16_t id, struct fd_dns_txt *out);

#endif /* ZCL_INSTALL_FRONT_DOOR_H */
