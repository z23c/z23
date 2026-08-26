/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * public_shape_fixture — real license text for package fixtures.
 *
 * The public-hosting rule (vcs/package_public_shape.h) reads the LICENSE
 * bytes and holds them against the SPDX identifier the signed envelope
 * declares, so a fixture that ships "MIT\n" is refused exactly as a real
 * package shipping "MIT\n" would be. Tests that mean to be HOSTABLE embed
 * the genuine text from here; tests that mean to prove REFUSAL ship the
 * placeholder deliberately. */

#ifndef ZCL_TEST_PUBLIC_SHAPE_FIXTURE_H
#define ZCL_TEST_PUBLIC_SHAPE_FIXTURE_H

/* The MIT license, verbatim. */
#define TEST_LICENSE_TEXT_MIT                                                  \
    "MIT License\n"                                                            \
    "\n"                                                                       \
    "Copyright (c) 2026 Z23 test fixture\n"                                    \
    "\n"                                                                       \
    "Permission is hereby granted, free of charge, to any person obtaining a " \
    "copy\n"                                                                   \
    "of this software and associated documentation files (the \"Software\"), " \
    "to deal\n"                                                                \
    "in the Software without restriction, including without limitation the "   \
    "rights\n"                                                                 \
    "to use, copy, modify, merge, publish, distribute, sublicense, and/or "    \
    "sell\n"                                                                   \
    "copies of the Software, and to permit persons to whom the Software is\n"  \
    "furnished to do so, subject to the following conditions:\n"               \
    "\n"                                                                       \
    "The above copyright notice and this permission notice shall be included " \
    "in all\n"                                                                 \
    "copies or substantial portions of the Software.\n"                        \
    "\n"                                                                       \
    "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, "       \
    "EXPRESS OR\n"                                                             \
    "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF "                 \
    "MERCHANTABILITY,\n"                                                       \
    "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT "       \
    "SHALL THE\n"                                                              \
    "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n" \
    "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, "         \
    "ARISING FROM,\n"                                                          \
    "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS "  \
    "IN THE\n"                                                                 \
    "SOFTWARE.\n"

/* The Apache License 2.0 grant notice, verbatim from the license's own
 * "APPENDIX: How to apply the Apache License to your work". This is the
 * license TEXT (a grant, a warranty disclaimer, and the canonical location
 * of the full terms), not the SPDX identifier, so it satisfies the frozen
 * permissive-text authority the same way a real Apache-2.0 package does. */
#define TEST_LICENSE_TEXT_APACHE_2_0                                           \
    "Copyright 2026 Z23 test fixture\n"                                        \
    "\n"                                                                       \
    "Licensed under the Apache License, Version 2.0 (the \"License\");\n"      \
    "you may not use this file except in compliance with the License.\n"       \
    "You may obtain a copy of the License at\n"                                \
    "\n"                                                                       \
    "    http://www.apache.org/licenses/LICENSE-2.0\n"                         \
    "\n"                                                                       \
    "Unless required by applicable law or agreed to in writing, software\n"    \
    "distributed under the License is distributed on an \"AS IS\" BASIS,\n"    \
    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or "         \
    "implied.\n"                                                               \
    "See the License for the specific language governing permissions and\n"    \
    "limitations under the License.\n"

/* The lie the rule exists to refuse: an identifier where the text goes. */
#define TEST_LICENSE_TEXT_PLACEHOLDER "MIT\n"

#endif /* ZCL_TEST_PUBLIC_SHAPE_FIXTURE_H */
