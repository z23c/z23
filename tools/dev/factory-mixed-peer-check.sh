#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
set -euo pipefail
if [[ $# != 1 ]]; then
    printf 'usage: %s PEER_CHECK_DIR\n' "$0" >&2
    exit 2
fi
cd "$1"
tar -xf bundle.tar
sha256sum -c inputs.sha256 > input-check.log
gcc --version | head -1 > compiler.txt
gcc -std=c23 -Wall -Wextra -Werror -pedantic -O2 -Ipkg/include \
    pkg/src/history.c history_exhaustive.c -o history-exhaustive
./history-exhaustive 100 > exhaustive.log
gcc -std=c23 -Wall -Wextra -Werror -pedantic -O2 -Ipkg/include \
    pkg/src/history.c pkg/examples/history_cli.c -o history-cli
for count in $(seq 0 100); do
    sum=$((count * (count + 1) / 2))
    actual=$(./history-cli "$count")
    [[ $actual == "count=$count sum=$sum" ]]
    actual=$(./history-cli "$count" --json)
    [[ $actual == "{\"count\":$count,\"sum\":$sum}" ]]
done
for invalid in ' 75' '+75' '-0' '42949672960' ''; do
    status=0
    ./history-cli "$invalid" > /dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
done
printf 'terminal_text=101 terminal_json=101 invalid=5 pass\n' > terminal.log
sha256sum history-exhaustive history-cli pkg/src/history.c \
    pkg/include/history.h pkg/examples/history_cli.c > outputs.sha256
tar -cf result.tar compiler.txt input-check.log exhaustive.log terminal.log \
    outputs.sha256
sha256sum result.tar
