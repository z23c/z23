#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_vcs_no_git.sh — the ZVCS sovereignty gate (HARD).
#
# ZVCS is our OWN in-binary content-addressed VCS. The node binary must never
# shell out to git (or any external process) to do version control: git stays
# only as the out-of-band GitHub sha1 publish bridge (a script under
# tools/scripts/), never linked into or invoked from contexts/commons/modules/vcs/.
#
# This gate fails if any contexts/commons/modules/vcs/ source references git or a process-spawning
# primitive: the word `git`, or exec*/system(/popen(/fork(. Keeping contexts/commons/modules/vcs/
# free of these is what makes the VCS sovereign and reproducible.
#
# Fail-loud: a grep exit >=2 (bad pattern / unreadable tree) is a real error
# and aborts, never a hollow pass.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-vcs-no-git "$@"
