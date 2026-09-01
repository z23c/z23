# zarena

Bump (linear) arena allocator for C23.

Variable-size, aligned, O(1) allocations from one caller-owned
buffer with no per-object free. Reclaim wholesale with
`zarena_clear` or in LIFO order with `zarena_save`/`zarena_rewind`.
Ideal for parse trees, per-request scratch, and test fixtures where
every object dies together. Exhaustion returns NULL, never growth;
no malloc, no global state.

Tested for alignment, overlap, exhaustion, mark/rewind reuse, and
argument validation.

Apache-2.0 licensed.
