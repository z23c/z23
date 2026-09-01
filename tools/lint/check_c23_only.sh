#!/usr/bin/env bash
# Enforce the owner invariant that Z23 has no Rust build or link path.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ref_pattern='ZCL_WITH_RUST|librustzcash\.a|librustzcash_[A-Za-z0-9_]*|-lrust[A-Za-z0-9_]*|(^|[^A-Za-z0-9_])(cargo|rustc)([^A-Za-z0-9_]|$)'

if [[ "${1:-}" == "--selftest" ]]; then
    [[ 'cc -std=c23 main.c' =~ $ref_pattern ]] && exit 1
    [[ 'cargo build' =~ $ref_pattern ]] || exit 1
    [[ 'cc main.o -lrustzcash' =~ $ref_pattern ]] || exit 1
    printf 'check_c23_only selftest: OK\n'
    exit 0
fi

path_hits="$(git ls-files | awk '
    /(^|\/)(Cargo\.toml|Cargo\.lock|build\.rs)$/ || /\.rs$/ || /(^|\/)\.cargo\//
' || true)"

# Search the executable build/configuration surface. Historical prose and
# fixed vectors may name the implementation they were derived from, but no
# build script, manifest, runtime source, or linker configuration may offer a
# Rust toolchain/archive/FFI path.
ref_hits="$(git grep -n -E "$ref_pattern" -- \
    Makefile config app core domain lib ports adapters packages src tools \
    ':!contexts/wallet/domain/src/mnemonic.c' \
    ':!core/modules/sapling/src/circuit_gadgets.c' \
    ':!tools/lint/check_c23_only.sh' || true)"

if [[ -n "$path_hits" || -n "$ref_hits" ]]; then
    printf 'check_c23_only: FAIL — Z23 must have no Rust dependency\n' >&2
    [[ -z "$path_hits" ]] || printf '%s\n' "$path_hits" >&2
    [[ -z "$ref_hits" ]] || printf '%s\n' "$ref_hits" >&2
    exit 1
fi

printf 'check_c23_only: clean — no Rust source, manifest, build, link, or FFI path\n'
