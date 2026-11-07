<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Shipment SSH arguments

OpenSSH joins remote command arguments before the login shell parses them.
A remote-shell fixture reproduced the shipment argument loss: activation
received 20 arguments instead of 18, and rollback received 11 instead of 9.
The default budget `5 20 60` was split into three arguments.

Quoting each argument for the remote shell preserves both counts, the budget,
empty strings, and literal shell metacharacters. The fixture verifies that a
command embedded in an argument is not executed. The focused `dev_ship` test
passed with no skips; full lint passed all 224 gates on the code checkpoint.
