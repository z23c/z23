# engine/conditions/

**Shape:** Condition — `(detect, remedy, witness)` auto-healer.

Each file in `src/` is one Condition: a plain `static struct condition`
plus three file-static functions, registered with one line. There is no
block-DSL — `condition.h` defines only `CONDITION_MAX_NAME`,
`CONDITION_MAX_REGISTRY`, and the `struct condition` shape:

```c
static bool detect_fn(void);                         /* halt present?      */
static enum condition_remedy_result remedy_fn(void); /* attempt the fix    */
static bool witness_fn(int64_t target_at_detect);    /* confirm it worked  */

static struct condition c = {
    .name = "...", .severity = COND_WARN,
    .poll_secs = 5, .backoff_secs = 60, .max_attempts = 2,
    .detect = detect_fn, .remedy = remedy_fn, .witness = witness_fn,
    .witness_window_secs = 60,
};
void register_<name>(void) { condition_register(&c); }  /* registry calls this */
```

The condition engine (in `engine/modules/framework/condition.{c,h}`) polls every
registered condition, dispatches remedies under backoff, and pages the
operator only if `max_attempts` is exhausted with the witness still false.
Condition detail JSON is part of the AI/operator surface exposed through
`z23 dumpstate condition_engine`. When a remedy can return OK while the
condition still needs a witness (for example a no-advance stall that accepts
`height_not_found` but still requires an observed tip advance), the detail must
include the last remedy result and the witness facts that decide whether the
halt is still active. Agents should not have to reconstruct that from
`node.log`.

See [`docs/FRAMEWORK.md`](../../docs/FRAMEWORK.md) §"The canonical form is
struct-registration, not a block-DSL" (lines 198-226) and the exemplar
[`block_failed_mask_at_tip.c`](./src/block_failed_mask_at_tip.c).

**Every halt class becomes a file here.** This is the auto-resolution
substrate — see the source files in `src/` for the conditions shipped so
far (e.g. `block_failed_mask_at_tip.c`, `contradiction_frozen.c`, the
`snapshot_*` stall healers).
