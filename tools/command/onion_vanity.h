/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Vanity v3 onion identity search. A v3 address is
 * base32(pubkey || checksum || 0x03), so its leading characters are the
 * leading 5-bit groups of the 32-byte ed25519 public key. The search tests a
 * candidate seed by comparing those bits of the public key alone; the
 * checksum and the full address are computed once, for the winner. */
#ifndef ZCL_TOOLS_COMMAND_ONION_VANITY_H
#define ZCL_TOOLS_COMMAND_ONION_VANITY_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 12 characters is 60 bits, the most one 64-bit comparison covers. */
#define ONION_VANITY_PREFIX_MAX 12
#define ONION_VANITY_THREADS_MAX 64

enum onion_vanity_prefix_status {
    ONION_VANITY_PREFIX_OK = 0,
    ONION_VANITY_PREFIX_EMPTY,
    ONION_VANITY_PREFIX_TOO_LONG,
    ONION_VANITY_PREFIX_BAD_CHAR,
};

struct onion_vanity_target {
    char text[ONION_VANITY_PREFIX_MAX + 1]; /* lower-cased prefix */
    size_t length;
    unsigned bits;  /* 5 * length */
    uint64_t want;  /* the prefix as `bits` big-endian bits */
};

/* Validate and encode `prefix` (a-z, 2-7; upper case is lower-cased). On
 * ONION_VANITY_PREFIX_BAD_CHAR, *bad_char receives the first offending
 * character. */
enum onion_vanity_prefix_status
onion_vanity_target_parse(const char *prefix, struct onion_vanity_target *target,
                          char *bad_char);

/* True when the leading bits of `public_key` spell the target prefix. */
bool onion_vanity_pk_matches(const struct onion_vanity_target *target,
                             const uint8_t public_key[32]);

/* Mean number of candidates per match: 32^length. */
double onion_vanity_expected_tries(const struct onion_vanity_target *target);

enum onion_vanity_status {
    ONION_VANITY_FOUND = 0,
    ONION_VANITY_EXHAUSTED, /* max_tries reached */
    ONION_VANITY_TIMED_OUT,
    ONION_VANITY_INTERRUPTED,
    ONION_VANITY_FAILED, /* CSPRNG failure or invalid parameters */
};

struct onion_vanity_params {
    struct onion_vanity_target target;
    unsigned threads;                     /* 1..ONION_VANITY_THREADS_MAX */
    uint64_t max_tries;                   /* 0 = unbounded */
    int64_t timeout_ns;                   /* 0 = none */
    const atomic_int *interrupt;          /* may be NULL */
};

struct onion_vanity_result {
    enum onion_vanity_status status;
    uint8_t seed[32]; /* private key; valid only when status is FOUND */
    uint64_t tries;
    int64_t elapsed_ns;
};

/* Search with params->threads workers; the first match stops all of them.
 * Candidate seeds are fresh host-CSPRNG bytes. Every worker-side copy of
 * candidate key material is cleansed before return. The caller owns
 * result->seed and must cleanse it. */
void onion_vanity_search(const struct onion_vanity_params *params,
                         struct onion_vanity_result *result);

/* Candidates per second across `threads` workers over `duration_ns`;
 * 0.0 when the measurement did not complete. */
double onion_vanity_measure_rate(unsigned threads, int64_t duration_ns,
                                 const atomic_int *interrupt);

#endif
