#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_package_receipt_is_not_authority.sh — the package manifest is
# a LABEL, never a KEY.
#
# We are adding a "package manifest": a sidecar record beside a built
# hot-swap module .so that records its SHA3-256 digest, the consensus seal
# root it was compiled against, and its source TU/leaf set. Think of the .so
# as a disk and the manifest as the label glued to it: the label records what
# was tested, it does not decide what gets mounted.
#
# The single most dangerous thing that could happen to this design is the
# loader growing a "helpful" fast path that trusts the label instead of
# re-deriving the truth itself. The moment engine/modules/hotswap/ reads a manifest FILE
# off disk, forging that file becomes equivalent to mounting arbitrary code —
# the label would be authorizing the disk. Every real admission decision in
# this tree (hotswap_manifest_v2_validate in hotswap_loader.c, the seal-root
# pin in hotswap_activate.c) works from a COMPILED-IN symbol resolved by
# dlsym() against the .so itself, never from a sidecar file path. That
# distinction — dlsym'd data symbol vs. filesystem read — is exactly what
# this gate polices, because it is invisible to a human diff that only checks
# "does this still call hotswap_manifest_v2_validate somewhere".
#
# DISCRIMINATION RULE (how legitimate "manifest" mentions are told apart from
# a forbidden one): engine/modules/hotswap/src/hotswap_loader.c legitimately says
# "manifest" ~40 times — `zcl_hotswap_manifest_v2`, `MANIFEST_REJECT`,
# `manifest_copy`, `k_service_manifest` — all identifiers naming the OLD
# Tier-1 GENERATION manifest, a struct exported as a data symbol and read via
# dlsym(), never a file. None of those occurrences is a quoted string literal
# containing ".manifest", and none of them is the argument to a real
# filesystem call (fopen/open/openat/stat/lstat/access/opendir/readlink).
# This gate therefore does NOT ban the bare word "manifest" — it bans the
# three concrete shapes a file-backed manifest read would actually take:
#
#   1. A quoted string literal containing ".manifest" anywhere under
#      engine/modules/hotswap/src/ or engine/modules/hotswap/include/hotswap/ (a real path suffix
#      always shows up as a quoted literal; `prep.manifest->self_test`, a
#      bare struct-member access with no surrounding quotes, does not match).
#   2. A quoted string literal containing the new package-manifest schema
#      name "zcl.hotswap_package" anywhere in the same trees.
#   3. Any fopen/open/openat/stat/lstat/access/opendir/readlink call whose
#      own source line also mentions "manifest" (case-insensitive) — this
#      catches a path assembled into a variable (e.g. `manifest_path`) and
#      then opened, even without a literal ".manifest" suffix on that line.
#      dlsym() is deliberately NOT in this list: resolving the compiled-in
#      `zcl_hotswap_manifest_v2` data symbol is the legitimate mechanism this
#      gate exists to protect, not the thing it forbids.
#
# A fourth, separate leg proves the packaging tool that MINTS a package
# manifest (tools/dev/hotswap-package.sh, built by a different lane) is a
# DEV-ONLY tool: it lives under tools/dev/, no second copy of it exists
# anywhere the node compiles from, and no node source (lib/, app/, core/,
# src/) shells out to it. A build tool that writes labels is harmless; a node
# that can be made to exec one at runtime is not.
#
# NO SKIP PATH. If tools/dev/hotswap-package.sh does not exist yet (another
# lane owns it and may not have landed), that leg is FATAL — loud, exit 2 —
# never a silent pass. A gate that reports "clean" because its input hasn't
# shown up yet is a gate nobody can trust once it does.
#
# Ported to the C23 lint runtime (check-hotswap-package-receipt-is-not-
# authority in tools/lint/lintc/gate_hotswap_package_receipt_is_not_authority.c).
exec "$(dirname "$0")/../../build/bin/z23-lint" \
    check-hotswap-package-receipt-is-not-authority "$@"
