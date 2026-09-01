#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: Permanent born-green/red/exact-revert proof for the source transport HOT_FORK owner.

set -euo pipefail

ROOT="${ZCL_SOURCE_ROOT:-$(pwd -P)}"
BIN="${ZCL_DEV_BIN:-$ROOT/build/bin/zclassic23-dev}"
SOURCE="$ROOT/contexts/commons/modules/vcs/src/source_package_transport.c"
OUTPUT="${ZCL_REFLEX_TRANSPORT_ACCEPTANCE_OUTPUT:-$ROOT/build/dev-loop/reflex-hotfork-transport-acceptance.json}"

fail() { printf 'reflex-hotfork-transport-acceptance: %s\n' "$*" >&2; exit 2; }
[[ -x "$BIN" ]] || fail "missing dev binary: $BIN"
[[ -f "$SOURCE" && ! -L "$SOURCE" ]] || fail "owner source is not a regular file: $SOURCE"
command -v jq >/dev/null || fail 'jq is required'

backup="$(mktemp "${TMPDIR:-/tmp}/zcl-reflex-transport.XXXXXX")"
watcher_id=0
cleanup()
{
    if [[ "$watcher_id" -gt 0 ]]; then
        "$BIN" dev loop stop --input="{\"watcher_id\":$watcher_id}" \
            >/dev/null 2>&1 || true
    fi
    cp -p -- "$backup" "$SOURCE"
    rm -f -- "$backup"
}
trap cleanup EXIT INT TERM
cp -p -- "$SOURCE" "$backup"

begin="$($BIN dev begin)"
watcher_id="$(jq -er '.data.watcher_id' <<<"$begin")" || fail 'watcher id missing'
after="$(jq -er '.data.epoch' <<<"$begin")" || fail 'event cursor missing'
nonce="$(date +%s%N)"

drive_candidate()
{
    local candidate="$1" expected="$2" wait_for_edit=true event='' next loops
    chmod --reference="$SOURCE" "$candidate"
    mv -f -- "$candidate" "$SOURCE"
    result=''
    for ((loops = 0; loops < 16; loops++)); do
        result="$($BIN dev drive --input="{\"after_epoch\":$after,\"wait_for_edit\":$wait_for_edit,\"timeout_ms\":5000}")"
        event="$(jq -r '.data.event//""' <<<"$result")"
        next="$(jq -r '.data.epoch//0' <<<"$result")"
        [[ "$next" =~ ^[0-9]+$ && "$next" -gt "$after" ]] ||
            fail "event cursor did not advance: $(jq -c . <<<"$result")"
        after="$next"
        [[ "$event" == "$expected" || "$event" == STORY_RED ||
           "$event" == COMPILE_RED ]] && break
        wait_for_edit=false
    done
    jq -e --arg expected "$expected" '
      .ok==true and .data.event==$expected and
      .data.feedback_class=="HOT_FORK" and
      .data.story_fixture_id=="source-package-transport-shape.v1" and
      .data.story_adapter=="source-package-transport-shape.v1" and
      .data.story_timeout_ms==1000 and
      .data.forbidden_effect_mask==
        "git|github|make|shell|sqlite|dht|network|publication|full_link|full_suite" and
      .data.candidate_bytes_executed==true and
      .data.runtime_published==false and .data.feedback_us<1000000 and
      (.data.candidate_object_root|test("^[0-9a-f]{64}$")) and
      (.data.candidate_module_root|test("^[0-9a-f]{64}$")) and
      .data.loaded_mapping_root==.data.candidate_module_root and
      (.data.story_root|test("^[0-9a-f]{64}$")) and
      (.data.story_fixture_root|test("^[0-9a-f]{64}$")) and
      (.data.observation_root|test("^[0-9a-f]{64}$"))' \
      <<<"$result" >/dev/null ||
        fail "candidate did not return bound $expected: $(jq -c . <<<"$result")"
}

green="$(mktemp "$ROOT/contexts/commons/modules/vcs/src/.reflex-transport-green.XXXXXX")"
cp -p -- "$backup" "$green"
printf '\n/* ZCL_REFLEX_TRANSPORT_ACCEPTANCE:%s */\n' "$nonce" >>"$green"
drive_candidate "$green" STORY_GREEN
green_result="$result"
green_epoch="$after"

mutant="$(mktemp "$ROOT/contexts/commons/modules/vcs/src/.reflex-transport-red.XXXXXX")"
cp -p -- "$SOURCE" "$mutant"
perl -0pi -e 's/if \(index == 0\) \{/if (index == 1) {/' "$mutant"
[[ "$(LC_ALL=C grep -c 'if (index == 1) {' "$mutant")" -ge 1 ]] ||
    fail 'compile-valid semantic mutation was not staged'
drive_candidate "$mutant" STORY_RED
red_result="$result"
red_epoch="$after"

revert="$(mktemp "$ROOT/contexts/commons/modules/vcs/src/.reflex-transport-revert.XXXXXX")"
cp -p -- "$backup" "$revert"
printf '\n/* ZCL_REFLEX_TRANSPORT_ACCEPTANCE:%s */\n' "$nonce" >>"$revert"
drive_candidate "$revert" STORY_GREEN
revert_result="$result"
revert_epoch="$after"

green_raw="$($BIN dev loop wait --input="{\"after_epoch\":$((green_epoch-1)),\"timeout_ms\":100}")"
revert_raw="$($BIN dev loop wait --input="{\"after_epoch\":$((revert_epoch-1)),\"timeout_ms\":100}")"
jq -e --arg object "$(jq -r '.data.candidate_object_root' <<<"$green_result")" \
      --arg module "$(jq -r '.data.candidate_module_root' <<<"$green_result")" '
  .ok==true and .data.phase=="STORY_GREEN" and
  .data.build_receipt.artifact_cache_hit==true and
  .data.build_receipt.compiler_processes==0 and
  .data.build_receipt.linker_processes==0 and
  .data.candidate_object_root==$object and
  .data.candidate_module_root==$module' <<<"$revert_raw" >/dev/null ||
    fail 'exact revert did not reuse the exact verified capsule cache'

mkdir -p "$(dirname "$OUTPUT")"
jq -n --arg owner 'contexts/commons/modules/vcs/src/source_package_transport.c' \
  --argjson green "$green_result" --argjson red "$red_result" \
  --argjson revert "$revert_result" --argjson green_raw "$green_raw" \
  --argjson revert_raw "$revert_raw" '
  {schema:"zcl.reflex_owner_acceptance.v1",owner:$owner,
   green:{event:$green.data.event,feedback_us:$green.data.feedback_us,
          candidate_object_root:$green.data.candidate_object_root,
          candidate_module_root:$green.data.candidate_module_root,
          observation_root:$green.data.observation_root},
   born_red:{event:$red.data.event,feedback_us:$red.data.feedback_us,
             compile_valid:true,candidate_bytes_executed:true,
             observation_root:$red.data.observation_root},
   exact_revert:{event:$revert.data.event,
     feedback_us:$revert.data.feedback_us,
     artifact_cache_hit:$revert_raw.data.build_receipt.artifact_cache_hit,
     compiler_processes:$revert_raw.data.build_receipt.compiler_processes,
     linker_processes:$revert_raw.data.build_receipt.linker_processes,
     same_object:($green.data.candidate_object_root==
                  $revert.data.candidate_object_root),
     same_module:($green.data.candidate_module_root==
                  $revert.data.candidate_module_root)},
   runtime_published:false}' >"$OUTPUT"

"$BIN" dev loop stop --input="{\"watcher_id\":$watcher_id}" >/dev/null
watcher_id=0
cp -p -- "$backup" "$SOURCE"
printf 'reflex-hotfork-transport-acceptance: PASS receipt=%s\n' "$OUTPUT"
