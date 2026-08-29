<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Sync discovery liveness acceptance

Date: 2026-08-29T14:30:50-04:00 / 2026-08-29T18:30:50Z

Environment: GCC 16.1.1, AMD Ryzen 7 PRO 8840U.

## Question

Can an unauthenticated peer win discovery with a cheap but useless response,
then consume the longer artifact or onion-fetch budget and suppress a useful
peer?

## Result

No. Bundle discovery now admits a peer only to the download rotation for the
exact artifact commitment that peer advertised. Onion seed racing requires a
caller-validated usable endpoint, not merely HTTP 200 with a body. Artifact
bytes remain subject to the existing chunk, whole-file, and checkpoint gates.

## Repeatable evidence

```sh
make -j16 t-fast ONLY=boot_bundle_fetch
make -j16 t-fast ONLY=onion_seed_race
```

Both registered groups ran cold with zero failures and zero skips. The onion
group includes an HTTP-200-but-unusable response racing a usable directory;
only the usable directory can win. The bundle group proves that a stalled
advertiser is dropped and a surviving exact-manifest peer lands the verified
bundle.

