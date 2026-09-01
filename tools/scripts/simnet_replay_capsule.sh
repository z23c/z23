#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# simnet_replay_capsule.sh — replay one or more saved wire_sweep failure
# capsules deterministically.
#
# `tools/sim/wire_sweep.c` (see its file header) saves a failing seed's
# replay capsule as `<artifact-dir>/seed_0x<HEX>.tape` via the existing
# `simnet_wire_save_capsule()` (a plain `seed_tape_save()` file — the same
# format `docs/examples/09_seed_replay.c` and `engine/modules/sim/src/postmortem.c` use).
# The whole point of the seed-tape design ("every bug becomes a 64-bit
# seed", `docs/work/sim-phase2-plan.md`) is that the scenario is a *pure
# function of the scalar seed* — `wire_sweep_run_one(seed)` rebuilds the
# exact same peer archetype, sub-case, and event stream every time, with
# no dependency on the saved tape file's contents. So replaying a capsule
# does not need to parse or load the `.tape` file at all: it only needs
# the seed, which wire_sweep already encodes into the capsule's filename.
#
# This script is the "reuse, don't duplicate" glue: it finds capsule
# file(s), recovers each seed from its filename, and re-invokes the SAME
# wire_sweep binary with `--start=<seed> --count=1 --verbose` — the exact
# single-seed slice of the nightly sweep loop in wire_sweep.c's `main()`.
#
# Usage:
#   simnet_replay_capsule.sh <capsule-dir-or-.tape-file> <wire_sweep-bin> \
#                            [artifact-dir]
#
# Exit status: 0 if every replayed seed still reports PASS, 1 if any seed
# fails (monitor failure) or no capsule file was found, 2 on usage error.

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <capsule-dir-or-.tape-file> <wire_sweep-bin> [artifact-dir]" >&2
    exit 2
fi

cap_path=$1
wire_sweep_bin=$2
artifact_dir=${3:-build/simnet-repro-output}

if [ ! -x "$wire_sweep_bin" ]; then
    echo "simnet_replay_capsule: wire_sweep binary not found or not executable: $wire_sweep_bin" >&2
    exit 2
fi

if [ ! -e "$cap_path" ]; then
    echo "simnet_replay_capsule: no such capsule path: $cap_path" >&2
    exit 2
fi

# Collect candidate .tape files: a single file, or every top-level
# seed_0x*.tape file inside a directory (the exact set wire_sweep.c's
# wire_sweep_maybe_save_capsule() writes — see WIRE_SWEEP_ARTIFACT_DIR /
# --artifact-dir in the Makefile's `wire-sweep` target).
tape_files=()
if [ -d "$cap_path" ]; then
    while IFS= read -r -d '' f; do
        tape_files+=("$f")
    done < <(find "$cap_path" -maxdepth 1 -type f -name 'seed_0x*.tape' -print0 | sort -z)
elif [ -f "$cap_path" ]; then
    tape_files=("$cap_path")
else
    echo "simnet_replay_capsule: $cap_path is neither a directory nor a file" >&2
    exit 2
fi

if [ "${#tape_files[@]}" -eq 0 ]; then
    echo "simnet_replay_capsule: no seed_0x*.tape capsule files found under $cap_path" >&2
    echo "  (capsules are written by 'make wire-sweep' on a monitor failure," >&2
    echo "   default directory build/wire-sweep-output/)" >&2
    exit 1
fi

mkdir -p "$artifact_dir"

failures=0
replayed=0
for f in "${tape_files[@]}"; do
    base=$(basename -- "$f")
    seed_hex=$(printf '%s\n' "$base" | sed -n 's/^seed_\(0x[0-9a-fA-F]\{1,16\}\)\.tape$/\1/p')
    if [ -z "$seed_hex" ]; then
        echo "simnet_replay_capsule: skipping $f (name does not match seed_0x<HEX>.tape)" >&2
        continue
    fi
    replayed=$((replayed + 1))
    echo "==> replaying capsule $f (seed=$seed_hex)"
    if ! "$wire_sweep_bin" --start="$seed_hex" --count=1 --verbose \
            --artifact-dir="$artifact_dir"; then
        failures=$((failures + 1))
    fi
done

if [ "$replayed" -eq 0 ]; then
    echo "simnet_replay_capsule: found ${#tape_files[@]} file(s) but none matched seed_0x<HEX>.tape" >&2
    exit 1
fi

if [ "$failures" -ne 0 ]; then
    echo "simnet_replay_capsule: $failures/$replayed replayed seed(s) still FAIL"
    exit 1
fi

echo "simnet_replay_capsule: $replayed/$replayed replayed seed(s) PASS"
