<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Dependency ownership across linked checkouts

On 2026-11-17, a C23 compiler fixture compared the include dependencies
reported by Z23 source identity `5347024aa670` with GCC 14.2.0 on an AMD
Ryzen 9 7950X3D. GCC compiled one translation unit with an angle-bracket
include using `-Isrc -MMD`. The parent checkout then changed the include
from header A to header B while retaining its stale compiler depfile.
GCC's `-MM` output on the current parent source named B.

| Parent query for B | Include dimension | Reported dependents |
| --- | --- | --- |
| Parent build directory alone | closure-truncated | none |
| After compiling the same unit in a linked checkout under the parent build directory | complete | none |

The peer compiled the original source against A. Its fresh depfile had
the same translation unit name and cleared the parent's stale-input
refusal. The parent lost the signal that its dependency answer required
broader verification. Both rows came from separate CLI processes on the
same checkout. This fixture measures correctness.

The focused `codeindex_stale` regression on base `76ffcc4885` with the
worktree-boundary change passed on Linux. It checks that the parent
retains its stale-depfile refusal and that the peer-only edge is absent.
The test verdict recorded one group run, zero cached and zero failed.
Host admission took 401.6 seconds. The admitted build and test took
244.1 seconds including compilation.
