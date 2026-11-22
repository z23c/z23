<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Explicit selector pin preflight

On 2026-11-22, an AMD Ryzen 9 7950X3D host with Ubuntu Clang 20.1.8 ran `make -j8 agent-verify ONLY=@changed` through the admitted development entry with an explicitly missing all-zero commit. Times include Make and its children, in seconds; each invocation refused with exit 2.

| Source | Conditions | Wall | User | System |
| --- | --- | ---: | ---: | ---: |
| `d06ff1a4b3ccce4c04327721df450f5caefe34da` | initial | 28.91 | 11.81 | 9.30 |
| `9d4bbc18d56b66010d750041558115cde3ea52f6` | initial, Tor readiness not current | 25.10 | 10.17 | 6.31 |
| `9d4bbc18d56b66010d750041558115cde3ea52f6` | subsequent | 11.31 | 4.11 | 1.69 |
| `5a5dd3f67ccbdf886fa3b78070ca529ff8ac2ba2` | subsequent | 0.68 | 0.63 | 0.08 |
| `5a5dd3f67ccbdf886fa3b78070ca529ff8ac2ba2` | subsequent | 0.68 | 0.63 | 0.08 |

The initial preflight still allowed Make to prepare stale Tor inputs before running the recipe. The later source classifies a sole verification wrapper as a non-building entry: recursive and mixed build goals retain their own preparation. In a separate archive fixture with vendor, Tor and generated inputs absent and counted failing setup tools, the complete Makefile refused the missing pin without launching those tools or the compiler. Direct node and mixed wrapper/node controls reached the compiler gate. This is a single-host measurement, not a fleet estimate.

An isolated Git fixture exercised both selector modes against missing, divergent, historical, current, moved-ancestor and moved-divergent references: all 12 controls met their expected selection and refusal assertions. The fixture script SHA-256 was `bfc545d5af35670f4daf24797f64b5821f006b2b0ed52602d734b20cbab79408`; its selector preflight source was `9d4bbc18d56b66010d750041558115cde3ea52f6`.
