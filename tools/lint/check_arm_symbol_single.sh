#!/usr/bin/env bash
# Gate — a non-static function is defined ONCE per translation unit
# (ratchet, shrink-only <path>\t<function> baseline).
#
# THE BUG CLASS THIS CLOSES (found live, 2026-08-29).
# core/modules/net/src/file_service.c splits into a `#if defined(_WIN32)` arm and a
# POSIX `#else` arm. Three PURE request parsers — fs_parse_rom_request,
# fs_parse_rom_manifest_request, fs_parse_rom_list_request — had a full body
# in BOTH arms, and the bodies had drifted apart on two axes: Windows
# required an exact payload length and refused a NULL output pointer; POSIX
# accepted any payload at least the minimum length (silently ignoring
# trailing bytes) and treated the output pointers as optional, returning
# true having written nothing. A Windows node and a Linux node could
# therefore disagree about whether identical bytes on the wire are a valid
# request — a network-splitting bug, for functions that touch no platform
# API at all and had no reason to be inside the split in the first place.
#
# WHAT THIS GATE CHECKS. The C standard already forbids two unconditional
# definitions of one external symbol in a TU — the only way a file compiles
# with a name defined twice is if the two definitions sit in mutually
# exclusive preprocessor branches. So the general defect class is not
# "duplicated inside `#if defined(_WIN32)`" specifically — it is: a
# non-static function is DEFINED (has a body) more than once, anywhere, in
# one .c file. Whatever macro (`_WIN32`, `__linux__`, `ZCL_TESTING`, a CPU
# feature flag, ...) separates the copies, every one of them is a place two
# bodies can silently drift apart under one name.
#
# WHAT THIS DOES NOT PROVE. A duplicate is not automatically a bug: a real
# OS-abstraction "platform seam" (platform/modules/platform/src is the intentional home
# for exactly this shape — one function, N OS-specific bodies) or a real
# SIMD/feature dispatch pair can legitimately share a name across arms. This
# gate cannot tell "genuinely platform-dependent, correctly split" apart
# from "pure function, accidentally split, actively drifting" — that needs
# a human reading the two bodies. What it CAN do, and what it is for, is
# make every such pair visible so a human decides, instead of the bodies
# drifting in the dark the way the ROM parsers did. The baseline below is
# that visible list: every row is a reviewed, accepted duplicate (mostly
# genuine platform/feature/test arms); a row is removed only by fixing the
# file, never by widening the gate.
#
# WHAT IT CANNOT CHECK. It is a line-order scanner over C text, not a
# compiler (same limitation class as check_outparam_init_before_return.sh
# and check_byte_order_codec_single.sh):
#   - It does not expand macros, so a body produced entirely by a
#     function-defining macro (e.g. FS_WINDOWS_TRANSPORT_REFUSAL(name, args)
#     in file_service.c) is invisible — a real drift risk if the two arms'
#     macro expansions differ, but out of reach for a text scanner.
#   - `static` is detected by a token match on the signature's own line (or
#     the line immediately above it); a return type wrapped onto its own
#     separate line above THAT can hide a leading `static` and produce a
#     false "non-static" — the failure mode is over-reporting, not a missed
#     violation, and it has not been observed in this tree.
#   - `__attribute__((...))` and `__declspec(...)` prefixes are recognized
#     and skipped so they cannot be mistaken for the function name; a
#     C23 `[[...]]` attribute list is fine too (it has no parenthesis to
#     confuse the scanner) as long as it sits on the same physical line as
#     the signature it decorates.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#
# A baseline row that no longer matches (function fixed, or file deleted)
# must be DELETED, or the ratchet rusts shut at a stale list. That is
# reported as a failure too.
#
# --selftest plants: (1) two non-static bodies for the same name inside
# `#ifdef`/`#else` — must FAIL; (2) the same shape but both bodies `static`
# — must PASS (internal linkage, not this gate's class); (3) a
# `#define`-based function-generator macro invoked twice under different
# names — must PASS (no false hit from the macro's own `{`/`}`); (4) an
# `__attribute__((...))`-prefixed function on its own line above the
# signature — must PASS (the attribute must not be read as the function
# name); (5) one clean, singly-defined function — must PASS. A gate that
# cannot fail on (1) is worse than no gate; a gate that fires on (2)-(5) is
# noise that gets ignored.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-arm-symbol-single "$@"
