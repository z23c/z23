#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_unattended_publish — HARD gate, closed allowlist.
#
# THE RULE: no script in this repository may write to the shared remote.
# Publishing is a deliberate act a person performs, never a side effect of a
# background loop.
#
# WHAT MOTIVATED IT, measured 2026-08-26: tools/scripts/fleet_sync.sh ran on
# cron every ten minutes on four machines and pushed a "<box> sync heartbeat"
# commit to origin/main every cycle. Each commit carried that box's onion
# address, its P2P port, the source hash of the binary it was running, its
# peer count, whether it was up, and its last error. Three consequences, all
# bad: the public history filled with machine chatter, live operator state
# shipped to every reader of the repository, and a project anyone is supposed
# to be able to join looked like it had four designated boxes. It also meant
# an unattended timer could move `main` — the branch every other checkout
# fast-forwards from — with nobody reviewing what it pushed.
#
# The script no longer has such a path. This gate is what keeps it that way,
# and it exists because that script's own header asks for it by name.
#
# WHAT IS ALLOWED. The allowlist below is CLOSED and every entry carries a
# mandatory reason. A file not named there may not publish, and an unknown
# file is refused rather than assumed benign (fail closed). Three shapes are
# legitimate:
#   * the deliberate operator-run deploy path,
#   * a hook that only PRINTS advice mentioning the command,
#   * a lint fixture whose whole purpose is to contain the forbidden string.
# A sandbox that commits inside its own throwaway repo is not a publish and
# is not matched: only pushes and the low-level commit-tree plumbing are.
#
# WHY THESE TWO COMMANDS. `git push` is the obvious one. `git commit-tree` is
# the subtle one: it builds a commit object without touching the index or the
# working tree, so `git commit-tree ... | git push origin <sha>:main` moves a
# branch from a detached HEAD while leaving the checkout looking untouched.
# That is exactly the shape the heartbeat used, and a reviewer scanning for
# "git commit" would never have seen it.
#
# NATIVE LEAVES. A shell script spells `git push` as literal text; a native
# command under tools/command/*.c or tools/dev/*.c never does — it reaches
# git only through an argv array handed to util/spawn.h's zcl_spawn*(), so
# the shell-oriented regex above cannot see it. Those two directories are
# scanned separately for the shape that DOES show up in the source: a
# "push" subcommand literal and an "origin" remote literal in the same file
# that also calls a spawn function. tools/command/native_dev_land.c (the
# landing service, dev.land) is the one file that legitimately matches —
# see its ALLOW_PATHS row — and it is scanned like everything else, not
# exempted from the search.
#
# PIPEFAIL. Status-carrying substring tests go through str_contains from
# tools/scripts/sh_str.sh. `printf | grep -q` under `set -o pipefail` reports
# a MATCH as 141, which in a lint gate reads a FOUND VIOLATION as CLEAN — the
# precise failure that would make this gate hollow while looking green.
#
# Usage:
#   ./tools/lint/check_no_unattended_publish.sh            # FAIL mode
#   ./tools/lint/check_no_unattended_publish.sh --selftest # planted proof
#
# Exit: 0 clean, 1 violation, 2 the gate could not scan (loud, never quiet).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-unattended-publish "$@"
