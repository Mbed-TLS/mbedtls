#!/bin/sh

# 80-handshake-memory.sh
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


# Get handshake memory usage from server or client output and put it into the variable specified by the first argument
handshake_memory_get() {
    OUTPUT_VARIABLE="$1"
    OUTPUT_FILE="$2"

    # Get memory usage from a pattern like "Heap memory usage after handshake: 23112 bytes. Peak memory usage was 33112"
    MEM_USAGE=$(sed -n 's/.*Heap memory usage after handshake: //p' < "$OUTPUT_FILE" | grep -o "[0-9]*" | head -1)

    # Check if memory usage was read
    if [ -z "$MEM_USAGE" ]; then
        echo "Error: Can not read the value of handshake memory usage"
        return 1
    else
        eval "$OUTPUT_VARIABLE=$MEM_USAGE"
        return 0
    fi
}

# Get handshake memory usage from server or client output and check if this value
# is not higher than the maximum given by the first argument
handshake_memory_check() {
    MAX_MEMORY="$1"
    OUTPUT_FILE="$2"

    # Get memory usage
    if ! handshake_memory_get "MEMORY_USAGE" "$OUTPUT_FILE"; then
        return 1
    fi

    # Check if memory usage is below max value
    if [ "$MEMORY_USAGE" -gt "$MAX_MEMORY" ]; then
        echo "\nFailed: Handshake memory usage was $MEMORY_USAGE bytes," \
             "but should be below $MAX_MEMORY bytes"
        return 1
    else
        return 0
    fi
}

# Test that the server's memory usage after a handshake is reduced when a client specifies
# a maximum fragment length.
#  first argument ($1) is MFL for SSL client
#  second argument ($2) is memory usage for SSL client with default MFL (16k)
run_test_memory_after_hanshake_with_mfl()
{
    # The test passes if the difference is around 2*(16k-MFL)
    MEMORY_USAGE_LIMIT="$(( $2 - ( 2 * ( 16384 - $1 )) ))"

    # Leave some margin for robustness
    MEMORY_USAGE_LIMIT="$(( ( MEMORY_USAGE_LIMIT * 110 ) / 100 ))"

    run_test    "Handshake memory usage (MFL $1)" \
                "$P_SRV debug_level=3 auth_mode=required force_version=tls12" \
                "$P_CLI debug_level=3 force_version=tls12 \
                    crt_file=data_files/server5.crt key_file=data_files/server5.key \
                    force_ciphersuite=TLS-ECDHE-ECDSA-WITH-AES-128-CCM max_frag_len=$1" \
                0 \
                -F "handshake_memory_check $MEMORY_USAGE_LIMIT"
}

# Test that the server's memory usage after a handshake is reduced when a client specifies
# different values of Maximum Fragment Length: default (16k), 4k, 2k, 1k and 512 bytes
run_tests_memory_after_hanshake()
{
    # all tests in this sequence requires the same configuration (see requires_config_enabled())
    SKIP_THIS_TESTS="$SKIP_NEXT"

    # first test with default MFU is to get reference memory usage
    MEMORY_USAGE_MFL_16K=0
    run_test    "Handshake memory usage initial (MFL 16384 - default)" \
                "$P_SRV debug_level=3 auth_mode=required force_version=tls12" \
                "$P_CLI debug_level=3 force_version=tls12 \
                    crt_file=data_files/server5.crt key_file=data_files/server5.key \
                    force_ciphersuite=TLS-ECDHE-ECDSA-WITH-AES-128-CCM" \
                0 \
                -F "handshake_memory_get MEMORY_USAGE_MFL_16K"

    SKIP_NEXT="$SKIP_THIS_TESTS"
    run_test_memory_after_hanshake_with_mfl 4096 "$MEMORY_USAGE_MFL_16K"

    SKIP_NEXT="$SKIP_THIS_TESTS"
    run_test_memory_after_hanshake_with_mfl 2048 "$MEMORY_USAGE_MFL_16K"

    SKIP_NEXT="$SKIP_THIS_TESTS"
    run_test_memory_after_hanshake_with_mfl 1024 "$MEMORY_USAGE_MFL_16K"

    SKIP_NEXT="$SKIP_THIS_TESTS"
    run_test_memory_after_hanshake_with_mfl 512 "$MEMORY_USAGE_MFL_16K"
}
# Test heap memory usage after handshake
requires_config_enabled MBEDTLS_MEMORY_DEBUG
requires_config_enabled MBEDTLS_MEMORY_BUFFER_ALLOC_C
requires_config_enabled MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
requires_max_content_len 16384
run_tests_memory_after_hanshake
