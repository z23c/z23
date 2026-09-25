#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Purpose: reproduce mail outbox corruption after a short append and retry.
set -euo pipefail

dev_bin=${1:?pass the development binary}
scratch=${2:?pass an isolated scratch parent}
jsonq_bin=${3:?pass the native JSON query helper}
mkdir -p "$scratch"
fixture=$(mktemp -d "$scratch/mail-fsize.XXXXXX")
export XDG_STATE_HOME="$fixture/state"
body=$(printf '%0350d' 0)

limited=$(
    ulimit -f 1
    trap '' XFSZ
    for i in 1 2 3; do
        if reply=$("$dev_bin" dev agent mail --input="{\"action\":\"post\",\"from\":\"fixture\",\"to\":\"fixture\",\"kind\":\"note\",\"body\":\"$body\",\"ref\":\"fsize-$i\"}"); then
            rc=0
        else
            rc=$?
        fi
        ok=$(printf '%s\n' "$reply" | "$jsonq_bin" raw ok)
        code=$(printf '%s\n' "$reply" | "$jsonq_bin" raw error.code 2>/dev/null || :)
        bytes=$(wc -c < "$XDG_STATE_HOME/z23/dev/mail/outbox.jsonl")
        printf 'attempt=%s rc=%s ok=%s code=%s bytes=%s\n' \
            "$i" "$rc" "$ok" "$code" "$bytes"
    done
)
printf '%s\n' "$limited"
outbox="$XDG_STATE_HOME/z23/dev/mail/outbox.jsonl"
before_bytes=$(wc -c < "$outbox")
after=$("$dev_bin" dev agent mail --input='{"action":"post","from":"fixture","to":"fixture","kind":"note","body":"recovery","ref":"after-limit"}')
pull=$("$dev_bin" dev agent mail --input='{"action":"pull","since":"0"}')
post_ok=$(printf '%s\n' "$after" | "$jsonq_bin" raw ok)
post_seq=$(printf '%s\n' "$after" | "$jsonq_bin" raw data.seq)
pull_count=$(printf '%s\n' "$pull" | "$jsonq_bin" raw data.count)
third_seq=$(printf '%s\n' "$pull" | "$jsonq_bin" raw 'data.rows[2].seq')
third_ref=$(printf '%s\n' "$pull" | "$jsonq_bin" raw 'data.rows[2].ref')
after_bytes=$(wc -c < "$outbox")
printf 'post_ok=%s post_seq=%s pull_count=%s third_seq=%s third_ref=%s before_bytes=%s after_bytes=%s\n' \
    "$post_ok" "$post_seq" "$pull_count" "$third_seq" "$third_ref" "$before_bytes" "$after_bytes"
sha256sum "$outbox"

if [[ $limited == *'attempt=1 rc=0 ok=true'* &&
      $limited == *'attempt=2 rc=0 ok=true'* &&
      $limited == *'attempt=3 rc=1 ok=false'* &&
      $post_ok == true && $post_seq == 4 && $pull_count == 3 &&
      $third_seq == 3 && $third_ref == '"after-limit"' &&
      $before_bytes -eq 1024 && $after_bytes -gt $before_bytes ]]; then
    printf 'RED: failed append left a partial row; later success was not a separate readable row\n'
    exit 0
fi
printf 'INCONCLUSIVE: expected short-write counterexample was not observed\n' >&2
exit 1
