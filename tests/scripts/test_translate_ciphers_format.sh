#!/bin/sh

# test_translate_ciphers_format.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Purpose
#
# Test translate_ciphers.py formatting by comparing the translated
# ciphersuite names to the true names. As in compat.sh, the spaces between
# the ciphersuite names are normalised.
#
# On fail, the translated cipher suite names do not match the correct ones.
# In this case the difference will be printed in stdout.
#
# This files main purpose is to ensure translate_ciphers.py can take strings
# in the expected format and return them in the format compat.sh will expect.

set -eu

if cd $( dirname $0 ); then :; else
    echo "cd $( dirname $0 ) failed" >&2
    exit 1
fi

fail=0

# Initalize ciphers translated from Mbed TLS using translate_ciphers.py
O_TRANSLATED_CIPHERS=""
G_TRANSLATED_CIPHERS=""

# Initalize ciphers that are known to be in the correct format
O_CIPHERS=""
G_CIPHERS=""

# Mbed TLS ciphersuite names to be translated
# into GnuTLS and OpenSSL
CIPHERS="TLS-ECDHE-ECDSA-WITH-NULL-SHA      \
    TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA   \
    TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA    \
    TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA    \
    "

G=$(./translate_ciphers.py g $CIPHERS) || fail=1
G_TRANSLATED_CIPHERS="$G_TRANSLATED_CIPHERS $G"

O=$(./translate_ciphers.py o $CIPHERS) || fail=1
O_TRANSLATED_CIPHERS="$O_TRANSLATED_CIPHERS $O"

G_CIPHERS="$G_CIPHERS                     \
    +ECDHE-ECDSA:+NULL:+SHA1                \
    +ECDHE-ECDSA:+3DES-CBC:+SHA1            \
    +ECDHE-ECDSA:+AES-128-CBC:+SHA1         \
    +ECDHE-ECDSA:+AES-256-CBC:+SHA1         \
    "
O_CIPHERS="$O_CIPHERS             \
    ECDHE-ECDSA-NULL-SHA            \
    ECDHE-ECDSA-DES-CBC3-SHA        \
    ECDHE-ECDSA-AES128-SHA          \
    ECDHE-ECDSA-AES256-SHA          \
    "

# Mbed TLS ciphersuite names to be translated
# into GnuTLS and OpenSSL
CIPHERS="TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256          \
          TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384         \
          TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256         \
          TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384         \
         "

G=$(./translate_ciphers.py g $CIPHERS) || fail=1
G_TRANSLATED_CIPHERS="$G_TRANSLATED_CIPHERS $G"

O=$(./translate_ciphers.py o $CIPHERS) || fail=1
O_TRANSLATED_CIPHERS="$O_TRANSLATED_CIPHERS $O"

G_CIPHERS="$G_CIPHERS                             \
    +ECDHE-ECDSA:+AES-128-CBC:+SHA256               \
    +ECDHE-ECDSA:+AES-256-CBC:+SHA384               \
    +ECDHE-ECDSA:+AES-128-GCM:+AEAD                 \
    +ECDHE-ECDSA:+AES-256-GCM:+AEAD                 \
    "
O_CIPHERS="$O_CIPHERS             \
    ECDHE-ECDSA-AES128-SHA256       \
    ECDHE-ECDSA-AES256-SHA384       \
    ECDHE-ECDSA-AES128-GCM-SHA256   \
    ECDHE-ECDSA-AES256-GCM-SHA384   \
    "

# Normalise spacing
G_TRANSLATED_CIPHERS=$( echo $G_TRANSLATED_CIPHERS )
O_TRANSLATED_CIPHERS=$( echo $O_TRANSLATED_CIPHERS )

G_CIPHERS=$( echo $G_CIPHERS )
O_CIPHERS=$( echo $O_CIPHERS )

# Compare the compat.sh names with the translated names
# Upon fail, print them to view the differences
if [ "$G_TRANSLATED_CIPHERS" != "$G_CIPHERS" ]
then
    echo "GnuTLS Translated:    $G_TRANSLATED_CIPHERS"
    echo "GnuTLS Original:      $G_CIPHERS"
    fail=1
fi
if [ "$O_TRANSLATED_CIPHERS" != "$O_CIPHERS" ]
then
    echo "OpenSSL Translated: $O_TRANSLATED_CIPHERS"
    echo "OpenSSL Original:   $O_CIPHERS"
    fail=1
fi

exit $fail
