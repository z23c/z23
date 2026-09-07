#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# check-tor-full-default — real Tor is the default link, and a stub cannot be
# packaged.
#
# WHAT WENT WRONG, so nobody re-derives it. The node link selected real Tor
# when four archives happened to exist and fell back to libtor_stub.a when
# they did not. Nothing failed: the build compiled, linked, and passed the
# whole suite. The only symptom was a node whose -tor is inert — blind to the
# onion network this project is built on. Every fresh worktree hit it, because
# a git worktree does not populate submodules. The portable Linux release hit
# it ON PURPOSE, passing TOR_FULL= to make.
#
# A defect whose only symptom is silence needs a gate, because a test can only
# check the build it was compiled into. Three things must stay true:
#
#   (i)   a build that links a node ESTABLISHES the Tor archives first — the
#         default goal cannot quietly proceed without them;
#   (ii)  the stub is reachable only by naming it, ZCL_TOR=stub, and the knob
#         rejects any other value rather than guessing;
#   (iii) every step that packages a binary refuses a tor=stub one with the
#         SAME sentence, so an operator who hits it once can grep for it.
#
# This gate reads text, deliberately. It cannot run a Tor build, and a runtime
# test cannot see the ninety-nine builds that were configured differently.

exec "$(dirname "$0")/../../build/bin/z23-lint" check-tor-full-default "$@"
