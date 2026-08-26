/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2016-2019 The Zcash developers
 * Copyright (C) 2022-2026 zclassic Community
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_CLIENTVERSION_H
#define BITCOIN_CLIENTVERSION_H

#define CLIENT_VERSION_MAJOR 0
#define CLIENT_VERSION_MINOR 1
#define CLIENT_VERSION_REVISION 0
#define CLIENT_VERSION_BUILD 50

#if !defined(WINDRES_PREPROC)

#include <stdbool.h>
#include <stddef.h>

#define CLIENT_VERSION \
    (1000000 * CLIENT_VERSION_MAJOR + 10000 * CLIENT_VERSION_MINOR + \
     100 * CLIENT_VERSION_REVISION + CLIENT_VERSION_BUILD)

extern const char CLIENT_NAME[];

/* Defined ONLY in clientversion.c. Must not be a static inline: each TU would
 * freeze the baked metadata at its own last recompile, and version reporters
 * inside one binary could then disagree. The Makefile keeps clientversion.o
 * fresh through the source/build identity stamp. */
const char *zcl_build_commit(void);

/* Compatibility getters for display fields. They return "external": Git
 * commit ids are deliberately not baked into the sovereign executable because
 * its exact bytes are receipt authority. GitHub publication may carry commit
 * trace metadata in an external sidecar. */
const char *zcl_build_commit_full(void);

/* Exact 64-hex lowercase SHA-256 emitted by
 * tools/dev/source-identity.sh capture (zcl.dev_source_identity.v2), or
 * "unknown" when the build was not source-stamped. This is the authoritative
 * source-tree input for producer receipt v2; Git/GitHub commit metadata is not
 * part of that receipt's digests.
 *
 * SCOPE — this answers exactly one question: "what source tree was THIS
 * EXECUTABLE compiled from?" It is the compile-time constant ZCL_BUILD_SOURCE_ID
 * and nothing else: it reads no file, no environment variable, and no working
 * directory, so it returns the same bytes no matter where the process is run
 * from or what is checked out around it. That property is what makes it usable
 * as the deploy freshness authority — a running daemon can be compared against
 * the build that was supposed to be installed.
 *
 * It is NOT "what source tree is in this directory right now". That is a
 * different question with a different, directory-dependent answer, computed by
 * tools/dev/source-identity.sh over a checkout and surfaced as the Makefile's
 * $(BUILD_SOURCE_ID). Reporting that one under this one's name would let a
 * freshness check pass a stale daemon whose own checkout happens to be current.
 * Anything that must stay directory-independent belongs here; anything derived
 * from a checkout must be named after the checkout. See the TWO QUESTIONS block
 * at the top of tools/scripts/source_identity_lib.sh for the shell-side rule and
 * the readers that enforce it. */
const char *zcl_build_source_id_sha256(void);

/* Dev/test-only build-session ABA receipt, or "unknown" in reproducible
 * sovereign/release and unstamped standalone binaries. This host-local token
 * must never become consensus, publication, or executable-byte authority. */
const char *zcl_build_source_mutation_sha256(void);

/* Native Merkle/CAS root bound into resident DEV_RESTART candidates. Normal
 * build/release artifacts return "unknown"; their publication identity
 * remains zcl_build_source_id_sha256(). */
const char *zcl_build_source_cas_sha3(void);

void FormatVersion(int nVersion, char *out, size_t out_size);

#endif /* WINDRES_PREPROC */
#endif
