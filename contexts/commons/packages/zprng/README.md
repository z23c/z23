# zprng

SplitMix64 seeding plus the xoshiro256** PRNG, in freestanding C23.

Fast deterministic pseudo-randomness for simulations, fuzzing,
games, and reproducible tests: any 64-bit seed (including 0) is
expanded by SplitMix64 into a xoshiro256** state with period
2^256-1. Includes unbiased bounded draws (Lemire rejection),
[0,1) doubles, and Fisher-Yates shuffling.

- `zsplitmix64_init` / `next` — seed expansion stream
- `zxoshiro256ss_init` / `next` — 64-bit generator
- `zxoshiro256ss_below` / `double` / `shuffle` — sampling helpers

Tested against reference SplitMix64/xoshiro256** vectors plus
determinism, bucket-coverage, range, and permutation checks.

Not cryptographically secure — use a CSPRNG for secrets.

Apache-2.0 licensed.
