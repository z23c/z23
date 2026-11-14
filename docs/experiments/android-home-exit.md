<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android Home unexpected exit

Home reports an unexpected node exit using the existing restart policy observation.
The restart observation fixture checks the view signal, retry transition, and explicit
stop reset. The Home fixture checks the displayed state. Android physical UI proof
is NOTRUN. The observed node startup failure has a separate, unresolved cause.
