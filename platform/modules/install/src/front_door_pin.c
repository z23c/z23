/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: parse a z23-pin-v1 release pin and judge whether the three
 * consistency channels agree — the whole decision the install front door
 * makes, with no I/O in it.
 *
 * Ported byte-for-byte in behaviour from the pin_parse / consider /
 * attest_arg trio that used to live in platform/packaging/install/install.sh and, a
 * second time and by hand, in packaging/install/install.ps1. Two independent
 * implementations of one security judgement drift; the drift is invisible
 * until the day the two answer differently about whether to install
 * something. There is now one.
 */

#include "install/front_door.h"

#include <stdio.h>
#include <string.h>

const char FD_PIN_SENTINEL[] =
    "z23-pin-v1:"
    "0000000000000000000000000000000000000000000000000000000000000000:"
    "0000000000000000000000000000000000000000000000000000000000000000";

static const char k_prefix[] = "z23-pin-v1:";

static bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
           c == '\v' || c == '\f';
}

/* Copy `text` into `out` with surrounding ASCII whitespace removed. Returns
 * false when the trimmed value cannot fit, which is itself a rejection: a
 * pin is a fixed 140 characters and anything longer is not one. */
static bool trim_into(const char *text, char *out, size_t out_len)
{
    if (!text || out_len == 0)
        return false;
    while (*text && is_space(*text))
        text++;
    size_t n = strlen(text);
    while (n > 0 && is_space(text[n - 1]))
        n--;
    if (n >= out_len)
        return false;
    memcpy(out, text, n);
    out[n] = '\0';
    return true;
}

static bool is_sha256_hex(const char *s, size_t n)
{
    if (n != FD_HEX_LEN)
        return false;
    for (size_t i = 0; i < n; i++) {
        const char c = s[i];
        const bool digit = c >= '0' && c <= '9';
        const bool lower = c >= 'a' && c <= 'f';
        if (!digit && !lower)
            return false;
    }
    return true;
}

bool fd_pin_is_sentinel(const char *text)
{
    char trimmed[FD_PIN_MAX];
    if (!trim_into(text, trimmed, sizeof trimmed))
        return false;
    return strcmp(trimmed, FD_PIN_SENTINEL) == 0;
}

bool fd_pin_parse(const char *text, struct fd_pin *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof *out);

    char trimmed[FD_PIN_MAX];
    if (!trim_into(text, trimmed, sizeof trimmed))
        return false;
    /* The unset sentinel declares that nothing is pinned. It is NOT a pin,
     * and reporting it as one would install the all-zero release. */
    if (strcmp(trimmed, FD_PIN_SENTINEL) == 0)
        return false;
    if (strncmp(trimmed, k_prefix, sizeof k_prefix - 1) != 0)
        return false;

    const char *rest = trimmed + (sizeof k_prefix - 1);
    const char *colon = strchr(rest, ':');
    if (!colon)
        return false;
    const size_t manifest_len = (size_t)(colon - rest);
    const char *installer = colon + 1;
    /* A third colon means this is some other record shape wearing our
     * prefix. Refuse rather than take the first two fields of it. */
    if (strchr(installer, ':') != NULL)
        return false;
    if (!is_sha256_hex(rest, manifest_len))
        return false;
    if (!is_sha256_hex(installer, strlen(installer)))
        return false;

    memcpy(out->text, trimmed, strlen(trimmed) + 1);
    memcpy(out->manifest, rest, FD_HEX_LEN);
    out->manifest[FD_HEX_LEN] = '\0';
    memcpy(out->installer, installer, FD_HEX_LEN);
    out->installer[FD_HEX_LEN] = '\0';
    return true;
}

bool fd_pin_from_lines(const char *blob, struct fd_pin *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!blob)
        return false;

    const char *p = blob;
    while (*p) {
        const char *nl = strchr(p, '\n');
        const size_t n = nl ? (size_t)(nl - p) : strlen(p);
        /* An over-long line cannot be a pin; skip it rather than truncate it
         * into something that might parse. */
        if (n < FD_PIN_MAX) {
            char line[FD_PIN_MAX];
            memcpy(line, p, n);
            line[n] = '\0';
            if (fd_pin_parse(line, out))
                return true;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    memset(out, 0, sizeof *out);
    return false;
}

static void copy_bounded(char *dst, size_t dst_len, const char *src)
{
    if (dst_len == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t n = strlen(src);
    if (n >= dst_len)
        n = dst_len - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void fd_attestation_answered(struct fd_attestation *a, const char *origin,
                             const struct fd_pin *pin)
{
    if (!a)
        return;
    memset(a, 0, sizeof *a);
    copy_bounded(a->origin, sizeof a->origin, origin);
    if (pin)
        a->pin = *pin;
    a->answered = pin != NULL;
    if (!a->answered)
        copy_bounded(a->reason, sizeof a->reason, "no-answer");
}

void fd_attestation_unreachable(struct fd_attestation *a, const char *origin,
                                const char *reason)
{
    if (!a)
        return;
    memset(a, 0, sizeof *a);
    copy_bounded(a->origin, sizeof a->origin, origin);
    copy_bounded(a->reason, sizeof a->reason, reason);
    a->answered = false;
}

/* Append "origin=reason" to the comma-separated unreachable list, exactly as
 * `UNREACHABLE="$UNREACHABLE${UNREACHABLE:+, }$1=$3"` did. A truncated list
 * would be a quiet lie about what was missing, so the buffer is sized for all
 * three sources at their longest and the append refuses to run past it. */
static void unreachable_append(char *list, size_t list_len,
                               const char *origin, const char *reason)
{
    const size_t used = strlen(list);
    const char *sep = used > 0 ? ", " : "";
    const int want = snprintf(list + used, list_len - used, "%s%s=%s",
                              sep, origin, reason);
    if (want < 0 || (size_t)want >= list_len - used)
        list[used] = '\0';
}

void fd_agree(const struct fd_attestation *att, size_t count,
              struct fd_agreement *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof *out);
    out->total = count;
    if (!att)
        count = 0;

    const struct fd_attestation *first = NULL;
    for (size_t i = 0; i < count; i++) {
        const struct fd_attestation *a = &att[i];
        if (!a->answered) {
            unreachable_append(out->unreachable, sizeof out->unreachable,
                               a->origin, a->reason);
            continue;
        }
        out->answered++;
        if (!first) {
            first = a;
            continue;
        }
        if (strcmp(a->pin.text, first->pin.text) != 0) {
            /* Two sources that both answered say different things. This is
             * the loudest refusal we have and it is never resolved by a
             * majority: a rollback, a half-finished publish and a compromise
             * all look exactly like this, and installing the more popular
             * answer would hide every one of them. */
            out->verdict = FD_VERDICT_DISAGREE;
            copy_bounded(out->first_origin, sizeof out->first_origin,
                         first->origin);
            copy_bounded(out->first_pin, sizeof out->first_pin,
                         first->pin.text);
            copy_bounded(out->other_origin, sizeof out->other_origin,
                         a->origin);
            copy_bounded(out->other_pin, sizeof out->other_pin, a->pin.text);
            return;
        }
    }

    if (out->answered < 2) {
        /* One source is not corroboration. There is deliberately no silent
         * degradation to a single channel here. */
        out->verdict = FD_VERDICT_NO_QUORUM;
        return;
    }
    out->verdict = FD_VERDICT_AGREED;
    out->agreed = first->pin;
}

bool fd_attest_arg(const struct fd_attestation *a, char *out, size_t out_len)
{
    if (!a || !out || out_len == 0)
        return false;
    const int want = a->answered
        ? snprintf(out, out_len, "--attest=%s=%s", a->origin, a->pin.text)
        : snprintf(out, out_len, "--attest-unreachable=%s=%s", a->origin,
                   a->reason);
    if (want < 0 || (size_t)want >= out_len) {
        out[0] = '\0';
        return false;
    }
    return true;
}
