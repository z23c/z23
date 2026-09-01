#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Enforce the owner invariant that Z23 has no Python runtime path.
# Compiled code is C23. Operator glue is shell or an in-tree C23 helper.
# Historical vector comments may name a Python origin; they must not invoke it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Invocation / shebang / runtime — not prose that names the ban.
# "no python (banned)" is documentation; python3/python2 and `python -c`
# / shebangs are the runtime path.
ref_pattern='(^|[|;&[:space:]])(python3|python2)([[:space:]]|$)|[[:space:]]python[[:space:]]+-|command -v python3|#!/usr/bin/env python|#!/usr/bin/python'

if [[ "${1:-}" == "--selftest" ]]; then
    [[ 'cc -std=c23 main.c' =~ $ref_pattern ]] && exit 1
    [[ 'Never use Python.' =~ $ref_pattern ]] && exit 1
    [[ 'No python (banned), no jq' =~ $ref_pattern ]] && exit 1
    [[ 'python3 -c "print(1)"' =~ $ref_pattern ]] || exit 1
    [[ '#!/usr/bin/env python3' =~ $ref_pattern ]] || exit 1
    [[ 'command -v python3' =~ $ref_pattern ]] || exit 1
    printf 'check_no_python selftest: OK\n'
    exit 0
fi

path_hits="$(git ls-files | awk '/\.py$/ || /(^|\/)__pycache__\//' || true)"

ref_hits="$(git grep -n -E "$ref_pattern" -- \
    AGENTS.md CLAUDE.md README.md Makefile config app core domain lib \
    ports adapters packages src tools docs \
    ':!tools/lint/check_no_python.sh' \
    ':!tests/harness/src/test_mnemonic.c' \
    ':!tests/harness/src/test_domain_wallet_mnemonic.c' \
    ':!contexts/commons/packages/zu256/tests/vectors.h' \
    || true)"

filtered="$ref_hits"

if [[ -n "$path_hits" || -n "$filtered" ]]; then
    printf 'check_no_python: FAIL — Z23 must have no Python dependency\n' >&2
    [[ -z "$path_hits" ]] || printf '%s\n' "$path_hits" >&2
    [[ -z "$filtered" ]] || printf '%s\n' "$filtered" >&2
    exit 1
fi

printf 'check_no_python: clean — no Python source, shebang, or runtime path\n'
