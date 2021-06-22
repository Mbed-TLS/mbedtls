#!/bin/sh
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

set -eu

if [ -d include/mbedtls ]; then :; else
    echo "$0: must be run from root" >&2
    exit 1
fi

HEADERS=$( ls include/mbedtls/*.h include/psa/*.h tests/include/test/drivers/*.h | egrep -v 'compat-2\.x\.h' )
HEADERS="$HEADERS library/*.h"
HEADERS="$HEADERS 3rdparty/everest/include/everest/everest.h 3rdparty/everest/include/everest/x25519.h"

sed -n -e 's/.*#define \([a-zA-Z0-9_]*\).*/\1/p' $HEADERS \
    | egrep -v '^(asm|inline|EMIT|_CRT_SECURE_NO_DEPRECATE)$|^MULADDC_' \
    | sort -u > macros

# For include/mbedtls/config_psa.h need to ignore the MBEDTLS_xxx define
# in that file since they may not be defined in include/psa/crypto_config.h
# This line renames the potentially missing defines to ones that should
# be present.
sed -ne 's/^MBEDTLS_PSA_BUILTIN_/MBEDTLS_PSA_ACCEL_/p' <macros >>macros

wc -l macros
