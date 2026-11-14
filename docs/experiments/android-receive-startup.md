<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Receive during startup

On the installed 1ec857 Android app, Receive briefly reported an address read
failure during startup, then recovered automatically on the same page. This
change shows a neutral read failure with a read-only retry. Physical verification
of this change: NOTRUN.
