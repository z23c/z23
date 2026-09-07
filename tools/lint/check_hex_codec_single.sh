#!/usr/bin/env bash
# Gate — ONE hex codec (ratchet, shrink-only file list).
#
# What it enforces
# ----------------
# Base-16 encode/decode of a byte buffer lives in exactly one place:
# platform/modules/base/include/base/hex.h (zcl_hex_encode / zcl_hex_decode /
# zcl_hex_decode_lower / zcl_hex_decode_n / zcl_hex_nibble). No production
# file outside platform/modules/base may carry its own.
#
# Why
# ---
# platform/modules/encoding exported only the raw `p_util_hexdigit` lookup table, never a
# bytes<->hex function, so every module that needed one wrote it again.
# Measured when this gate was written: 56 files. They did not agree —
# some validated the input length, some did not; some accepted A-F, some
# silently rejected it; one used sscanf("%2x") and so accepted " 1" and
# "+1"; several left the caller's buffer half-written on a failed decode,
# and native_zcode_reward_command.c then read an uninitialised 32-byte root
# out of one of them. A codec pile is not a style problem: each copy is an
# independent chance to disagree about what a valid input is.
#
# Unit of measurement
# -------------------
# Per FILE, by two independent shape detectors, either of which marks the
# file as carrying a codec:
#
#   ENCODER — a lowercase/uppercase hex-digit TABLE ("0123456789abcdef")
#             anywhere in the file, AND a high-nibble index somewhere in the
#             file (">> 4)" or ">> 4]"). Both together, because either alone
#             is common and innocent: the table is also a charset validator
#             and a random-id alphabet, and ">> 4" is ordinary bit work.
#   DECODER — nibble-ladder arithmetic ("- 'a' + 10" / "- 'A' + 10") or a
#             two-digit hex scanf ("%2x").
#
# File granularity, not per-function: a shell scan cannot reliably bound a C
# function, and a gate that guesses is a gate that lies. Over-attribution is
# harmless here — a file with no codec matches neither detector.
#
# Excluded from the scan, with reasons:
#   platform/modules/base/  — the canonical home. It IS the codec.
#   tests/harness/include/test/  — a test fixture must parse its known-answer vectors with an
#                implementation independent of the one under test. Checking
#                zcl_hex_decode with zcl_hex_decode proves nothing.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#
# A baseline row that no longer matches must be DELETED, or the ratchet
# rusts shut at a stale list. That is reported as a failure too.
#
# --selftest plants a fresh encoder and a fresh decoder in a sandbox and
# requires a FAIL on each, then a file that calls the canonical helpers and
# requires a PASS — so a gate whose regexes have quietly stopped matching
# cannot keep reporting PASS.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-hex-codec-single "$@"
