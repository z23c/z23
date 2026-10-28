<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Landing queue read guidance

A status read with a regular file in place of the landing state directory
returned `QUEUE_READ_FAILED` with `queue_read_failed_errno_20` and advised
checking permissions and free space of a directory named in the evidence. The
evidence was an error identifier, not a directory name.

The read failure guidance now asks the operator to check path types and read
permissions, and to query the host that owns the queue when the local queue is
intentionally disabled. The error code and evidence remain unchanged. An
isolated fixture checks the guidance, the non-mutation flag, and unchanged file
bytes.

On 2026-10-28, `devbuild --wait --project z23 --class normal make -j8
t-fast-exact ONLY=dev_land` passed 176 of 176 scenarios with no skips. Two
preceding attempts failed at compilation while the fixture was being corrected.
