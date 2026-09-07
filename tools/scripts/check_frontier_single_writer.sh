#!/usr/bin/env bash
# Architecture gate — one canonical writer per durable frontier.
#
# The manifest names each frontier, its canonical owner basename, and the ERE
# that identifies a write. Existing debt is explicit in the ratchet baseline;
# any new non-owner writer fails. As Q2 removes cloned writers, delete their
# baseline rows until this becomes a zero-debt hard invariant.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-frontier-single-writer "$@"
