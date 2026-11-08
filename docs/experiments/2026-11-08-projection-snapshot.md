<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Retained projection snapshot

A retained read-only projection snapshot pins a SQLite read transaction and
reuses a prepared hash lookup. The caller keeps its directory namespace stable.
SQLite may update existing WAL shared memory. The reader does not establish
header validity or publish a chain view.

On an isolated fixture, `make t-fast-exact ONLY=block_index_projection_shard_07
T_FAST_EXACT_ARGS=--no-cache` passed with no skips. The fixture checked snapshot
isolation across a committed update, absent and malformed rows, cancellation,
namespace replacement, and refusal of a WAL without its shared-memory file.
The result does not measure phone startup or qualify a cold-prefix loader.
