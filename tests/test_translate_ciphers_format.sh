#!/bin/sh

# test_translate_format.sh
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

# Ciphers that will use translate_ciphers.py
M_CIPHERS=""
O_CIPHERS=""
G_CIPHERS=""

# Ciphers taken directly from compat.sh
Mt_CIPHERS=""
Ot_CIPHERS=""
Gt_CIPHERS=""

# Initial list to be split into 3
CIPHERS="TLS-ECDHE-ECDSA-WITH-NULL-SHA      \
    TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA   \
    TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA    \
    TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA    \
    "

M_CIPHERS="$M_CIPHERS $CIPHERS"

G=`python3 translate_ciphers.py g "$CIPHERS"`
G_CIPHERS="$G_CIPHERS $G"

O=`python3 translate_ciphers.py o "$CIPHERS"`
O_CIPHERS="$O_CIPHERS $O"

Mt_CIPHERS="$Mt_CIPHERS                       \
    TLS-ECDHE-ECDSA-WITH-NULL-SHA           \
    TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA   \
    TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA    \
    TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA    \
    "
Gt_CIPHERS="$Gt_CIPHERS                       \
    +ECDHE-ECDSA:+NULL:+SHA1                \
    +ECDHE-ECDSA:+3DES-CBC:+SHA1            \
    +ECDHE-ECDSA:+AES-128-CBC:+SHA1         \
    +ECDHE-ECDSA:+AES-256-CBC:+SHA1         \
    "
Ot_CIPHERS="$Ot_CIPHERS               \
    ECDHE-ECDSA-NULL-SHA            \
    ECDHE-ECDSA-DES-CBC3-SHA        \
    ECDHE-ECDSA-AES128-SHA          \
    ECDHE-ECDSA-AES256-SHA          \
    "


# Initial list to be split into 3
CIPHERS="TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256         \
          TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384         \
          TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256         \
          TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384         \
         "

M_CIPHERS="$M_CIPHERS $CIPHERS"

G=`python3 translate_ciphers.py g "$CIPHERS"`
G_CIPHERS="$G_CIPHERS $G"

O=`python3 translate_ciphers.py o "$CIPHERS"`
O_CIPHERS="$O_CIPHERS $O"

Mt_CIPHERS="$Mt_CIPHERS                               \
    TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256         \
    TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384         \
    TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256         \
    TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384         \
    "
Gt_CIPHERS="$Gt_CIPHERS                               \
    +ECDHE-ECDSA:+AES-128-CBC:+SHA256               \
    +ECDHE-ECDSA:+AES-256-CBC:+SHA384               \
    +ECDHE-ECDSA:+AES-128-GCM:+AEAD                 \
    +ECDHE-ECDSA:+AES-256-GCM:+AEAD                 \
    "
Ot_CIPHERS="$Ot_CIPHERS               \
    ECDHE-ECDSA-AES128-SHA256       \
    ECDHE-ECDSA-AES256-SHA384       \
    ECDHE-ECDSA-AES128-GCM-SHA256   \
    ECDHE-ECDSA-AES256-GCM-SHA384   \
    "

# Normalise spacing
M_CIPHERS=$( echo "$M_CIPHERS" | sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//')
G_CIPHERS=$( echo "$G_CIPHERS" | sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//')
O_CIPHERS=$( echo "$O_CIPHERS" | sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//')

Mt_CIPHERS=$( echo "$Mt_CIPHERS" | sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//')
Gt_CIPHERS=$( echo "$Gt_CIPHERS" | sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//')
Ot_CIPHERS=$( echo "$Ot_CIPHERS" | sed -e 's/[[:space:]][[:space:]]*/ /g' -e 's/^ //' -e 's/ $//')

# Compare the compat.sh names with the translated names
# Upon fail, print them to view the differences
if [ "$Mt_CIPHERS" != "$M_CIPHERS" ]
then
    echo "MBEDTLS Translated:   $M_CIPHERS"
    echo "MBEDTLS Original:     $Mt_CIPHERS"
fi
if [ "$Gt_CIPHERS" != "$G_CIPHERS" ]
then
    echo "GNUTLS Translated:    $G_CIPHERS"
    echo "GNUTLS Original:      $Gt_CIPHERS"
fi
if [ "$Ot_CIPHERS" != "$O_CIPHERS" ]
then
    echo "OpenSSL Translated: $O_CIPHERS"
    echo "OpenSSL Original:   $Ot_CIPHERS"
fi
