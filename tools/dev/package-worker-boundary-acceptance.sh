#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# A harmless constructor witness for the external package test worker.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
verifier="${1:-$repo_root/build/bin/zclassic23-package-verify}"
test -x "$verifier" || { echo 'package verifier is not built' >&2; exit 2; }
scratch="$(mktemp -d /tmp/z23-package-boundary.XXXXXXXX)"
trap 'rm -rf -- "$scratch"' EXIT
mkdir "$scratch/build"
printf 'harmless witness only\n' >"$scratch/fake-secret"

cat >"$scratch/witness.c" <<'EOF'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned witness_bits;
__attribute__((constructor)) static void before_main(void)
{
    char byte;
    if (fcntl(200, F_GETFD) >= 0) witness_bits |= 1u;
    if (read(STDIN_FILENO, &byte, 1) == 1) witness_bits |= 2u;
    if (getenv("Z23_HARMLESS_SECRET")) witness_bits |= 4u;
    int secret = open("../fake-secret", O_RDONLY);
    if (secret >= 0) { witness_bits |= 8u; close(secret); }
#ifdef TEST_NETWORK
    int network = socket(AF_INET, SOCK_STREAM, 0);
    if (network >= 0) { witness_bits |= 16u; close(network); }
#endif
}
int main(void)
{
    printf("constructor_witness_bits=%u\n", witness_bits);
    return witness_bits ? 40 + (int)witness_bits : 0;
}
EOF

"${CC:-cc}" -std=c2x -Wall -Wextra -Werror -o "$scratch/build/test.bin" \
    "$scratch/witness.c"
exec 200<"$scratch/fake-secret"
result="$(Z23_HARMLESS_SECRET=harmless "$verifier" \
    "--zbuild-test-input=$scratch/build/test.bin" \
    "--zbuild-test-output=$scratch/build/test.evidence.v1" \
    --require-full-isolation <"$scratch/fake-secret")"
exec 200<&-
printf '%s\n' "$result"
test -s "$scratch/build/test.evidence.v1"
case "$result" in
    *'zbuild-test-ok=1 verdict=pass exit=0 signal=0 timeout=0'*) ;;
    *) echo 'package constructor observed inherited authority or failed' >&2; exit 1 ;;
esac

# The Linux seccomp profile may kill a forbidden socket syscall; Seatbelt may
# instead return an error to the constructor. Both are valid denials. A live
# socket makes the constructor return 56 and must never qualify.
rm "$scratch/build/test.evidence.v1"
"${CC:-cc}" -std=c2x -Wall -Wextra -Werror -DTEST_NETWORK \
    -o "$scratch/build/test.bin" "$scratch/witness.c"
network_result="$(Z23_HARMLESS_SECRET=harmless "$verifier" \
    "--zbuild-test-input=$scratch/build/test.bin" \
    "--zbuild-test-output=$scratch/build/test.evidence.v1" \
    --require-full-isolation <"$scratch/fake-secret")"
printf '%s\n' "$network_result"
case "$network_result" in
    *'verdict=fail exit=0 signal=31 timeout=0'*|\
    *'verdict=pass exit=0 signal=0 timeout=0'*) ;;
    *) echo 'network constructor did not observe qualified denial' >&2; exit 1 ;;
esac
test -s "$scratch/build/test.evidence.v1"
