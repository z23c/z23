<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Chain snapshot tip pair

2026-11-14: A fixture placed the cached chain window one block ahead of the
registered height authority. The original snapshot paired the authority height
with the cached window tip hash. Both ordinary and bounded snapshot assertions
failed on that parent source. The corrected snapshot reads the hash from the
cached slot at the observed height, leaving a missing slot unknown.

The parent witness used `make t-fast-exact ONLY=test_chain_state_repo` through
`devbuild --wait`. The final candidate must pass the same group and its
registered landing gates before publication.
