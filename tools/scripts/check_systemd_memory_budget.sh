#!/usr/bin/env bash
# Lint gate: systemd hard memory caps must fit inside the host budget.
#
# This guards the host-level OOM class from recurring. It parses committed
# systemd units plus drop-ins, sums finite MemoryMax and MemorySwapMax values,
# and fails when the aggregate budget reaches/exceeds the configured reference
# host budget. The shipped profiles target the measured 96 GiB operator-host
# class; lint must not change verdict merely because a developer builds on a
# smaller machine. Deploy validation can override the reference through
# ZCL_SYSTEMD_MEMORY_BUDGET_MEMTOTAL_BYTES. Explicit MemoryMax=infinity is a
# hard failure because it disables a cap deliberately; absent MemoryMax remains
# allowed for lightweight units.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-systemd-memory-budget "$@"
