#!/usr/bin/env bash
# Gate — no NEW runtime abort primitive in network-reachable code
# (ratchet, shrink-only counts).
#
# What it enforces
# ----------------
# `assert()` IS LIVE IN THIS BUILD. `-DNDEBUG` appears in exactly two places
# in the tree, both of them the vendored LevelDB compile
# (tools/scripts/build_vendor.sh:222 and :566); the node's own CFLAGS
# (Makefile, `CFLAGS = -std=c23 -g -O3 ...`) never define it. So every
# `assert()` compiled into the node is a live `abort()` on failure, and every
# `assert()` sitting on a path that a peer, an RPC argument, an explorer URL
# segment or a stored blob can reach is a remote process-kill primitive.
#
# That is not hypothetical. The Base58 codec under every address, WIF,
# extended key and explorer lookup enforced its assumptions with assert()
# until 2026-07-28; so did BIP32 public child derivation, and so did
# extended-public-key serialization. One malformed input took the whole
# process down. They now return false and log a reason. This gate exists so
# that pile cannot re-form.
#
# Unit of measurement
# -------------------
# Per FILE: the number of RUNTIME `assert(` / `abort(` sites. A file's count
# may only shrink. A file absent from the baseline may have zero.
#
# What is NOT a site
# ------------------
#   * `_Static_assert(...)` / `static_assert(...)` — compile-time, and GOOD.
#     They are the correct replacement for a runtime assertion about a
#     layout or a constant, so a gate that flagged them would push the
#     codebase in exactly the wrong direction. The `[^_[:alnum:]]` prefix
#     guard is what separates them; ~32 of the ~44 naive `assert` hits in
#     the scan set are static assertions.
#   * Anything inside a comment. Note that a per-line `sub(/\/\*.*/, "")`
#     is NOT sufficient: the rationale comments this project writes are
#     multi-line block comments, and the word `assert()` lands on a
#     CONTINUATION line that carries no `/*` of its own (see
#     platform/domain/encoding/src/base58.c, contexts/wallet/modules/keys/src/key.c,
#     contexts/wallet/modules/keys/src/pubkey.c, core/modules/sapling/src/incremental_merkle_tree.c).
#     This gate therefore carries a real block-comment state machine.
#   * Anything inside a string literal.
#   * A site carrying the inline escape hatch (below).
#
# The escape hatch:  // abort-ok:<reason>
# -----------------------------------------
# Mirrors the established `// raw-return-ok:<reason>` idiom in
# check_silent_error_returns.sh. Some aborts are CORRECT and must not be
# softened into a `return false`:
#
#   core/modules/sapling/src/note_encryption.c — an `esk` repeat means the AEAD key is
#     about to be reused under the fixed zero nonce. Continuing leaks
#     plaintext; a crash does not.
#   contexts/wallet/modules/keys/src/key.c, contexts/wallet/modules/keys/src/pubkey.c — creation and teardown of the
#     process-wide secp256k1 signing/verification contexts, and a failure of
#     the entropy source feeding them. No external input reaches these, both
#     run exactly once, and a node that carried on would silently accept or
#     reject signatures.
#   core/modules/sapling/src/sapling.c — a fixed Jubjub generator that failed to
#     derive from hard-coded inputs. Every subsequent scalar multiplication
#     would produce garbage.
#
# Those are annotated in place rather than buried in the baseline, so the
# baseline stays a list of genuine debt that may only shrink, and nobody is
# ever pressured into "fixing" a correct abort to lower a number.
# The hatch requires a reason of at least 6 characters; `// abort-ok:` alone
# is not accepted.
#
# Scan set
# --------
# Named network-reachable roots only, not the whole tree. A whole-tree scan
# produces a baseline dominated by boot-only and tooling code, which dilutes
# the signal until nobody reads it. `core/` IS counted and frozen — it holds
# the consensus predicates and is byte-sealed, so forbidding new assertions
# there is exactly right even though the existing ones cannot be edited
# without the owner unseal ritual.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#
# --selftest plants each case into a sandbox and asserts the verdict, so a
# gate that has quietly stopped matching cannot report PASS. The
# `_Static_assert` case is a NEGATIVE control and is non-negotiable.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-runtime-abort "$@"
