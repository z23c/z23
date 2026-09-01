# zdogdrone

Circling gunner pilot for the `zdogfight` arena (C23).

The baseline opponent every other pilot must beat, and the born-red
reference for determinism tests: a pure integer function of the bounded
`zdog_obs` observation with no state, no randomness, no I/O. Strategy:
hold a constant gentle bank to fly a wide circle at cruise throttle and
fire whenever the nearest enemy is inside 120 m.

## Pilot ABI

One function:

```c
void zdogdrone_step(const zdog_obs *obs, zdog_ctl *out);
```

Same observation in -> same controls out, on any machine and any
compiler. The arena runner sandboxes the pilot process and feeds it
one 82-byte observation frame per living plane per tick; the pilot
answers with one 7-byte control frame.

`app/main.c` is the reference pilot-process loop (stdin/stdout pipe
protocol, malformed frame = loud exit, EOF = match over).

## License

Apache-2.0
