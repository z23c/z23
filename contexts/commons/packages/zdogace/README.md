# zdogace

Pursuit pilot for the `zdogfight` arena (C23).

A deterministic starter pilot: a pure integer function of the bounded
`zdog_obs` observation — no state between calls, no randomness, no I/O,
no allocation, no clock. Strategy: bank-to-turn pursuit of the nearest
enemy (roll toward the lateral bearing error via a 2D cross product,
pitch toward the elevation error), full throttle, fire when roughly
aligned and inside 300 m.

## Pilot ABI

One function:

```c
void zdogace_step(const zdog_obs *obs, zdog_ctl *out);
```

Same observation in -> same controls out, on any machine and any
compiler. The arena runner sandboxes the pilot process and feeds it
one 82-byte observation frame per living plane per tick; the pilot
answers with one 7-byte control frame.

`app/main.c` is the reference pilot-process loop (stdin/stdout pipe
protocol, malformed frame = loud exit, EOF = match over).

## License

Apache-2.0
