#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Verify that receipt admission cannot acquire a shell or build authority.

set -euo pipefail

files=(
    tools/dev/z23_git_hook.c
    tools/dev/dev_proof_receipt.c
    tools/dev/dev_proof_receipt.h
)

for file in "${files[@]}"; do
    [[ -f "$file" ]] || {
        echo "native proof fast path: missing $file" >&2
        exit 1
    }
done

if git grep -nE '(^|[^[:alnum:]_])(system|popen)[[:space:]]*\(' -- "${files[@]}"; then
    echo "native proof fast path: shell-launching C API is forbidden" >&2
    exit 1
fi

if git grep -niE '"(bash|powershell|pwsh|cmd\.exe|sh)"|/bin/(ba)?sh|[[:space:]]-c"' -- "${files[@]}"; then
    echo "native proof fast path: shell executable or expansion is forbidden" >&2
    exit 1
fi

grep -Fq 'execvp(argv[0]' tools/dev/z23_git_hook.c
grep -Fq 'execl(binary, binary, "dev", "proof", "ensure"' \
    tools/dev/z23_git_hook.c
grep -Fq 'ZCL_DEV_PROOF_WIRE_BYTES' tools/dev/z23_git_hook.c

echo "native proof fast path: PASS (sealed receipt admission, no shell authority)"
