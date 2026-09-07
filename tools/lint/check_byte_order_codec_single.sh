#!/usr/bin/env bash
# Gate — ONE fixed-width byte-order codec (ratchet, shrink-only file list).
#
# What it enforces
# ----------------
# Loading and storing a 16/32/64-bit integer at a byte address in a declared
# byte order lives in exactly one place: platform/modules/base/include/base/serialize_le.h
# (zcl_write_u{16,32,64}_le / zcl_read_u{16,32,64}_le, the i32/i64 forms, and
# the u32/u64 big-endian pair). No production file outside platform/modules/base may carry
# its own — including via core/modules/crypto/include/crypto/common.h, which now
# forwards ReadLE/WriteLE to the canonical header rather than defining them.
#
# Why
# ---
# A canonical set already existed in crypto/common.h and only SEVEN files
# used it. Everyone else re-wrote the shift ladder as a file-private static:
# 23 hand-rolled helpers at the time this gate was written, across 11 files,
# under 18 different names for the same 8 lines. Two symptoms are worth
# naming, because they are what a codec pile actually costs:
#
#   - contexts/wallet/modules/zid defined the family THREE times inside ONE module, under three
#     prefixes (put_le64, zdesc_put_le64, zendp_put_le64) — three chances
#     for one module to disagree with itself about its own wire format.
#   - consensus_state_snapshot_candidate.c wrote a persisted 8-byte field
#     with `le64_encode` and consensus_state_snapshot_candidate_validate.c
#     read it back with `le64_decode`: the encoder and decoder for ONE field,
#     in two files, under two names, with nothing but a reader's memory
#     tying them together. Nothing would have failed at compile time if one
#     of them had been edited.
#
# Byte order is a wire and disk contract, so a disagreement between two
# copies is not a style regression, it is a corruption bug.
#
# Unit of measurement
# -------------------
# Per FILE, by three independent shape detectors, any of which marks the
# file as carrying a codec:
#
#   LADDER_LOOP  — an indexed shift loop over a byte array, i.e. a shift by
#                  `8 * i` / `8u * i` in either direction. This is the
#                  dominant form (14 of the 23).
#   LADDER_FLAT  — an unrolled ladder: a shift by 24 or 56 (the top byte of
#                  a 32- or 64-bit width) appearing with a byte-array
#                  subscript on the same line. Bare `>> 24` is NOT enough —
#                  it is ordinary bit work — so the subscript is required.
#   BSWAP        — a hand-rolled byte-swap: the 0x00FF00FF-family masks that
#                  only appear in one.
#
# File granularity, not per-function: a shell scan cannot reliably bound a C
# function, and a gate that guesses is a gate that lies.
#
# Excluded from the scan, with reasons:
#   platform/modules/base/  — the canonical home. It IS the codec.
#   tests/harness/include/test/  — a test MUST hold an independent implementation of what it
#                checks. test_byte_order_codec.c deliberately carries a
#                verbatim copy of all 23 replaced helpers and asserts the
#                canonical functions agree with them byte for byte; that is
#                the proof nothing on disk moved, and it only works because
#                the copies are still there.
#   core/      — byte-sealed (core/MANIFEST.sha3). Not editable by this
#                gate's audience, so flagging it would be noise that can
#                never be actioned. core/math/serialize.h is the stream
#                codec, a different shape, and core's two callers of the
#                fixed-width form reach it through crypto/common.h.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#
# A baseline row that no longer matches must be DELETED, or the ratchet
# rusts shut at a stale list. That is reported as a failure too.
#
# --selftest plants a fresh helper of each detected shape in a sandbox and
# requires a FAIL on each, then plants innocent files (a bare `>> 24`, a
# loop with no shift) and a canonical caller and requires a PASS — so a gate
# whose regexes have quietly stopped matching cannot keep reporting PASS.
#
# Ported to the C23 lint runtime (check-byte-order-codec-single in
# tools/lint/lintc/gate_byte_order_codec_single.c).
exec "$(dirname "$0")/../../build/bin/z23-lint" \
    check-byte-order-codec-single "$@"
